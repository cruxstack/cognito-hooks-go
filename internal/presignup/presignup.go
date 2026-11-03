// Package presignup implements the PreSignUp hook. A policy's actions decide
// whether a user may sign up and can set Cognito's auto-confirm and
// auto-verify flags. The policy can be given an email verification result
// for the new user's address.
package presignup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/aws/aws-lambda-go/events"

	"github.com/cruxstack/cognito-hooks-go/internal/action"
	"github.com/cruxstack/cognito-hooks-go/internal/cognito"
	"github.com/cruxstack/cognito-hooks-go/internal/logging"
	"github.com/cruxstack/cognito-hooks-go/internal/policy"
	"github.com/cruxstack/cognito-hooks-go/internal/verify"
)

// PolicyQuery is the rule the PreSignUp policy must define.
const PolicyQuery = "data.cognito_hook_presignup.result"

// TriggerPrefix starts every PreSignUp trigger source.
const TriggerPrefix = "PreSignUp_"

// Trigger sources sent to the PreSignUp trigger.
const (
	TriggerSignUp           = "PreSignUp_SignUp"
	TriggerAdminCreateUser  = "PreSignUp_AdminCreateUser"
	TriggerExternalProvider = "PreSignUp_ExternalProvider"
)

// Triggers lists every PreSignUp trigger source.
var Triggers = []string{TriggerSignUp, TriggerAdminCreateUser, TriggerExternalProvider}

// Actions a PreSignUp policy can return.
const (
	// ActionAllow allows the sign-up.
	ActionAllow = "signup.allow"
	// ActionDeny denies the sign-up. It takes an optional "reason", which is
	// shown to the user, and wins over ActionAllow.
	ActionDeny = "signup.deny"
	// ActionConfirmUser confirms the user without a code (autoConfirmUser).
	ActionConfirmUser = "user.confirm"
	// ActionVerifyEmail marks the email address verified (autoVerifyEmail).
	ActionVerifyEmail = "email.verify"
	// ActionVerifyPhone marks the phone number verified (autoVerifyPhone).
	ActionVerifyPhone = "phone.verify"
)

// Actions lists the actions a PreSignUp policy can return.
var Actions = []string{ActionAllow, ActionDeny, ActionConfirmUser, ActionVerifyEmail, ActionVerifyPhone}

// DefaultDenyReason is shown to the user when the policy denies a sign-up
// without a reason.
const DefaultDenyReason = "sign-up is not allowed"

// ErrPolicyFailed is returned to Cognito, which rejects the sign-up, when the
// policy fails or returns an invalid result. The details are logged, not
// returned, because Cognito shows the message to the user.
var ErrPolicyFailed = errors.New("the sign-up policy failed")

// Event is a PreSignUp trigger event.
type Event = events.CognitoEventUserPoolsPreSignup

// Response holds the flags Cognito reads from the hook's response.
type Response = events.CognitoEventUserPoolsPreSignupResponse

// DeniedError is returned to Cognito when the policy denies a sign-up.
// Cognito shows its message to the user as "PreSignUp failed with error
// <reason>."
type DeniedError struct {
	Reason string
}

func (e *DeniedError) Error() string { return e.Reason }

// PolicyInput is the policy's input document.
type PolicyInput struct {
	cognito.Header
	UserAttributes map[string]string `json:"userAttributes"`
	ValidationData map[string]string `json:"validationData"`
	ClientMetadata map[string]string `json:"clientMetadata"`
	// EmailVerification is set when verification ran for this event and the
	// address could be checked.
	EmailVerification *verify.Result `json:"emailVerification,omitempty"`
}

// NewPolicyInput builds the policy input for an event.
func NewPolicyInput(e *Event, v *verify.Result) PolicyInput {
	return PolicyInput{
		Header:            cognito.NewHeader(e.CognitoEventUserPoolsHeader),
		UserAttributes:    cognito.Map(e.Request.UserAttributes),
		ValidationData:    cognito.Map(e.Request.ValidationData),
		ClientMetadata:    cognito.Map(e.Request.ClientMetadata),
		EmailVerification: v,
	}
}

// Decision is what the hook does with a sign-up, resolved from the policy's
// actions.
type Decision struct {
	// Actions are the actions the policy returned.
	Actions []action.Action `json:"actions"`
	// Allowed is false when the sign-up is denied.
	Allowed bool `json:"allowed"`
	// Reason is shown to the user when the sign-up is denied.
	Reason string `json:"reason,omitempty"`
	// Response holds Cognito's flags when the sign-up is allowed.
	Response Response `json:"response"`
}

// Decide evaluates the policy for one input and resolves its actions:
//
//   - signup.deny wins over signup.allow, so a policy can allow
//     unconditionally and deny in separate rules. The first denial's reason
//     is shown to the user.
//   - One of them is required; without either the result is invalid.
//   - user.confirm, email.verify, and phone.verify set Cognito's flags when
//     the sign-up is allowed.
//   - Unknown actions and parameters make the result invalid.
func Decide(ctx context.Context, p *policy.Engine, in PolicyInput) (*Decision, error) {
	res, err := policy.Eval[action.Result](ctx, p, in)
	if err != nil {
		return nil, err
	}
	if err := res.Check(); err != nil {
		return nil, err
	}

	d := &Decision{Actions: res.Actions}
	var allowed, denied bool
	for _, a := range res.Actions {
		var err error
		switch a.Name {
		case ActionAllow:
			allowed, err = true, a.Decode(&struct{}{})
		case ActionDeny:
			var params struct {
				Reason string `json:"reason"`
			}
			err = a.Decode(&params)
			if !denied {
				d.Reason = strings.TrimSpace(params.Reason)
			}
			denied = true
		case ActionConfirmUser:
			d.Response.AutoConfirmUser, err = true, a.Decode(&struct{}{})
		case ActionVerifyEmail:
			d.Response.AutoVerifyEmail, err = true, a.Decode(&struct{}{})
		case ActionVerifyPhone:
			d.Response.AutoVerifyPhone, err = true, a.Decode(&struct{}{})
		default:
			err = action.Unknown(a, "PreSignUp", Actions)
		}
		if err != nil {
			return nil, err
		}
	}

	switch {
	case denied:
		d.Response = Response{}
		if d.Reason == "" {
			d.Reason = DefaultDenyReason
		}
	case allowed:
		d.Allowed = true
	default:
		return nil, fmt.Errorf("policy result has neither %s nor %s", ActionAllow, ActionDeny)
	}
	return d, nil
}

// Config configures the hook.
type Config struct {
	Policy *policy.Engine
	// Verifier verifies the user's email address before the policy runs. Nil
	// disables verification.
	Verifier verify.Verifier
	// VerifyTriggers are the trigger sources the address is verified for.
	VerifyTriggers []string
}

// Hook handles PreSignUp events.
type Hook struct {
	policy         *policy.Engine
	verifier       verify.Verifier
	verifyTriggers []string
}

// New returns the hook.
func New(cfg Config) (*Hook, error) {
	if cfg.Policy == nil {
		return nil, errors.New("presignup: a policy is required")
	}
	return &Hook{policy: cfg.Policy, verifier: cfg.Verifier, verifyTriggers: cfg.VerifyTriggers}, nil
}

// Handle decides one sign-up. It sets the event's response when the policy
// allows the sign-up, and returns a *DeniedError when the policy denies it.
// It fails closed: when the policy fails, it returns ErrPolicyFailed and
// Cognito rejects the sign-up.
func (h *Hook) Handle(ctx context.Context, e *Event) error {
	email := strings.TrimSpace(e.Request.UserAttributes["email"])
	ctx = logging.WithAttrs(ctx, slog.String("email", logging.MaskEmail(email)))

	d, err := Decide(ctx, h.policy, NewPolicyInput(e, h.verify(ctx, e.TriggerSource, email)))
	if err != nil {
		slog.ErrorContext(ctx, "sign-up rejected because the policy failed", "error", err)
		return ErrPolicyFailed
	}

	if !d.Allowed {
		slog.InfoContext(ctx, "sign-up denied", "reason", d.Reason)
		return &DeniedError{Reason: d.Reason}
	}

	e.Response = d.Response
	slog.InfoContext(ctx, "sign-up allowed",
		"auto_confirm_user", e.Response.AutoConfirmUser,
		"auto_verify_email", e.Response.AutoVerifyEmail,
		"auto_verify_phone", e.Response.AutoVerifyPhone,
	)
	return nil
}

// verify returns the verification result for the address, or nil when
// verification is off for this trigger, there is no address, or the address
// could not be checked.
func (h *Hook) verify(ctx context.Context, trigger, email string) *verify.Result {
	if h.verifier == nil || email == "" || !slices.Contains(h.verifyTriggers, trigger) {
		return nil
	}

	r, err := h.verifier.Verify(ctx, email)
	if err != nil {
		slog.WarnContext(ctx, "email verification unavailable, policy runs without it", "error", err)
		return nil
	}
	slog.InfoContext(ctx, "email verified",
		"provider", r.Provider,
		"verdict", r.Verdict,
		"score", r.Score,
		"disposable", r.Disposable,
		"role", r.Role,
	)
	return r
}
