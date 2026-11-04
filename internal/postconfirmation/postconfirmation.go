// Package postconfirmation implements the PostConfirmation hook. It runs
// after a user confirms their sign-up or resets their password, and carries
// out the actions its optional policy returns. By default (password.replace)
// it replaces the password of each native user with a random one that nobody
// knows, so the user can only sign in with passwordless factors such as email
// or SMS one-time passwords and passkeys.
package postconfirmation

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"

	"github.com/cruxstack/cognito-hooks-go/internal/action"
	"github.com/cruxstack/cognito-hooks-go/internal/cognito"
	"github.com/cruxstack/cognito-hooks-go/internal/logging"
	"github.com/cruxstack/cognito-hooks-go/internal/password"
	"github.com/cruxstack/cognito-hooks-go/internal/policy"
	"github.com/cruxstack/cognito-hooks-go/internal/rotation"
)

// PolicyQuery is the rule the optional PostConfirmation policy must define.
const PolicyQuery = "data.cognito_hook_postconfirmation.result"

// TriggerPrefix starts every PostConfirmation trigger source.
const TriggerPrefix = "PostConfirmation_"

// Trigger sources sent to the PostConfirmation trigger.
const (
	// TriggerConfirmSignUp follows ConfirmSignUp and AdminConfirmSignUp.
	// Cognito doesn't send it for users created with AdminCreateUser.
	TriggerConfirmSignUp = "PostConfirmation_ConfirmSignUp"
	// TriggerConfirmForgotPassword follows ConfirmForgotPassword.
	TriggerConfirmForgotPassword = "PostConfirmation_ConfirmForgotPassword"
)

// Actions a PostConfirmation policy can return.
const (
	// ActionReplacePassword replaces the user's password with a random one.
	// It is the default when the policy returns no password action, and it
	// wins over ActionSkipPassword.
	ActionReplacePassword = "password.replace"
	// ActionSkipPassword keeps the user's password. It takes an optional
	// "reason", which is logged.
	ActionSkipPassword = "password.skip"
)

// Actions lists the actions a PostConfirmation policy can return.
var Actions = []string{ActionReplacePassword, ActionSkipPassword}

// PasswordLength is the length of the random password set on each user. A
// user pool's minimum password length can be up to 99, and Cognito accepts
// passwords of up to 256 characters.
const PasswordLength = 128

// UserStatusExternalProvider is the cognito:user_status of federated users.
const UserStatusExternalProvider = "EXTERNAL_PROVIDER"

// RecordTimeout bounds recording a replacement in the rotation table.
const RecordTimeout = 500 * time.Millisecond

// Event is a PostConfirmation trigger event.
type Event = events.CognitoEventUserPoolsPostConfirmation

// CognitoAPI is the part of the Cognito API the hook calls.
type CognitoAPI interface {
	AdminSetUserPassword(ctx context.Context, params *cip.AdminSetUserPasswordInput, optFns ...func(*cip.Options)) (*cip.AdminSetUserPasswordOutput, error)
}

// PolicyInput is the policy's input document.
type PolicyInput struct {
	cognito.Header
	UserAttributes map[string]string `json:"userAttributes"`
	ClientMetadata map[string]string `json:"clientMetadata"`
}

// NewPolicyInput builds the policy input for an event.
func NewPolicyInput(e *Event) PolicyInput {
	return PolicyInput{
		Header:         cognito.NewHeader(e.CognitoEventUserPoolsHeader),
		UserAttributes: cognito.Map(e.Request.UserAttributes),
		ClientMetadata: cognito.Map(e.Request.ClientMetadata),
	}
}

// Decision is what the hook does for a user, resolved from the policy's
// actions.
type Decision struct {
	// Actions are the actions the policy returned; empty without a policy.
	Actions []action.Action `json:"actions"`
	// ReplacePassword is false when the password is kept.
	ReplacePassword bool `json:"replacePassword"`
	// Reason is why the password is kept.
	Reason string `json:"reason,omitempty"`
}

// DefaultDecision is the decision without a policy, and when the policy
// fails: replace the password.
func DefaultDecision() *Decision {
	return &Decision{Actions: []action.Action{}, ReplacePassword: true}
}

// Decide evaluates the policy for one input and resolves its actions:
//
//   - password.replace is the default, and wins over password.skip.
//   - Unknown actions and parameters make the result invalid.
func Decide(ctx context.Context, p *policy.Engine, in PolicyInput) (*Decision, error) {
	res, err := policy.Eval[action.Result](ctx, p, in)
	if err != nil {
		return nil, err
	}
	if err := res.Check(); err != nil {
		return nil, err
	}

	var replace, skip bool
	var reason string
	for _, a := range res.Actions {
		var err error
		switch a.Name {
		case ActionReplacePassword:
			replace, err = true, a.Decode(&struct{}{})
		case ActionSkipPassword:
			var params struct {
				Reason string `json:"reason"`
			}
			err = a.Decode(&params)
			if !skip {
				reason = strings.TrimSpace(params.Reason)
			}
			skip = true
		default:
			err = action.Unknown(a, "PostConfirmation", Actions)
		}
		if err != nil {
			return nil, err
		}
	}

	d := &Decision{Actions: res.Actions, ReplacePassword: replace || !skip}
	if d.Actions == nil {
		d.Actions = []action.Action{}
	}
	if !d.ReplacePassword {
		d.Reason = reason
	}
	return d, nil
}

// Config configures the hook.
type Config struct {
	Cognito CognitoAPI
	// Policy decides the actions for each user. Without one, every native
	// user's password is replaced.
	Policy *policy.Engine
	// Rotations, when set, records each replacement, so the PreAuthentication
	// hook doesn't replace the password again at the user's first sign-in.
	Rotations rotation.Store
}

// Hook handles PostConfirmation events.
type Hook struct {
	cognito   CognitoAPI
	policy    *policy.Engine
	rotations rotation.Store
}

// New returns the hook.
func New(cfg Config) (*Hook, error) {
	if cfg.Cognito == nil {
		return nil, errors.New("postconfirmation: a cognito client is required")
	}
	return &Hook{cognito: cfg.Cognito, policy: cfg.Policy, rotations: cfg.Rotations}, nil
}

// Handle runs the policy and carries out its decision. It never returns an
// error: Cognito has already confirmed the user, so failing would show the
// user an error without undoing anything. When the policy fails, the hook
// replaces the password anyway; a failed replacement is logged as "password
// replacement failed", and one that can't be recorded as "password
// replacement not recorded".
func (h *Hook) Handle(ctx context.Context, e *Event) error {
	ctx = logging.WithAttrs(ctx, slog.String("sub", e.Request.UserAttributes["sub"]))

	d := h.decide(ctx, e)

	switch {
	case e.Request.UserAttributes["cognito:user_status"] == UserStatusExternalProvider:
		// federated users have no cognito password
		slog.InfoContext(ctx, "password replacement skipped", "reason", "federated user")
	case !d.ReplacePassword:
		slog.InfoContext(ctx, "password replacement skipped", "reason", d.Reason)
	default:
		h.replacePassword(ctx, e)
	}
	return nil
}

// decide returns the policy's decision, or the default decision when there
// is no policy or it fails.
func (h *Hook) decide(ctx context.Context, e *Event) *Decision {
	if h.policy == nil {
		return DefaultDecision()
	}
	d, err := Decide(ctx, h.policy, NewPolicyInput(e))
	if err != nil {
		slog.ErrorContext(ctx, "policy failed, applying the default actions", "error", err)
		return DefaultDecision()
	}
	return d
}

func (h *Hook) replacePassword(ctx context.Context, e *Event) {
	pw, err := password.Generate(PasswordLength)
	if err != nil {
		slog.ErrorContext(ctx, "password replacement failed", "error", err)
		return
	}
	if _, err := h.cognito.AdminSetUserPassword(ctx, &cip.AdminSetUserPasswordInput{
		UserPoolId: aws.String(e.UserPoolID),
		Username:   aws.String(e.UserName),
		Password:   aws.String(pw),
		Permanent:  true,
	}); err != nil {
		slog.ErrorContext(ctx, "password replacement failed", "error", err)
		return
	}
	slog.InfoContext(ctx, "password replaced")
	h.record(ctx, e.Request.UserAttributes["sub"])
}

// record records the replacement when there is a rotation table. Without
// the record, the PreAuthentication hook replaces the password again at the
// user's next sign-in, so a failure is only logged.
func (h *Hook) record(ctx context.Context, sub string) {
	if h.rotations == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, RecordTimeout)
	defer cancel()
	if err := h.rotations.Record(ctx, sub, time.Now()); err != nil {
		slog.ErrorContext(ctx, "password replacement not recorded", "error", err)
	}
}
