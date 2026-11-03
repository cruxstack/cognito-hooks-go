// Package presignup implements the PreSignUp hook. A policy decides whether a
// user may sign up and can set Cognito's auto-confirm and auto-verify flags.
// The policy can be given an email verification result for the new user's
// address.
package presignup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/aws/aws-lambda-go/events"

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

// Policy actions.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

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

// Decision is the policy's result document.
type Decision struct {
	Action string `json:"action"`
	// Reason is shown to the user when the sign-up is denied.
	Reason string `json:"reason,omitempty"`
	// Response sets Cognito's flags when the sign-up is allowed.
	Response *Response `json:"response,omitempty"`
}

// Decide evaluates the policy for one input and validates the result.
func Decide(ctx context.Context, p *policy.Engine, in PolicyInput) (*Decision, error) {
	d, err := policy.Eval[Decision](ctx, p, in)
	if err != nil {
		return nil, err
	}

	d.Action = strings.ToLower(strings.TrimSpace(d.Action))
	switch d.Action {
	case ActionAllow:
		if d.Response == nil {
			d.Response = &Response{}
		}
	case ActionDeny:
		d.Reason = strings.TrimSpace(d.Reason)
		if d.Reason == "" {
			d.Reason = DefaultDenyReason
		}
		d.Response = nil
	case "":
		return nil, errors.New(`policy result has no "action"`)
	default:
		return nil, fmt.Errorf(`policy result has unknown action %q: must be "allow" or "deny"`, d.Action)
	}
	return &d, nil
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

	if d.Action == ActionDeny {
		slog.InfoContext(ctx, "sign-up denied", "reason", d.Reason)
		return &DeniedError{Reason: d.Reason}
	}

	e.Response = *d.Response
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
