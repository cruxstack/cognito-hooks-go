// Package postconfirmation implements the PostConfirmation hook. It replaces
// the password of each newly confirmed native user with a random one that
// nobody knows, so the user can only sign in with passwordless factors such
// as email or SMS one-time passwords and passkeys.
package postconfirmation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"

	"github.com/cruxstack/cognito-hooks-go/internal/cognito"
	"github.com/cruxstack/cognito-hooks-go/internal/logging"
	"github.com/cruxstack/cognito-hooks-go/internal/password"
	"github.com/cruxstack/cognito-hooks-go/internal/policy"
)

// PolicyQuery is the rule the optional PostConfirmation policy must define.
const PolicyQuery = "data.cognito_hook_postconfirmation.result"

// TriggerPrefix starts every PostConfirmation trigger source.
const TriggerPrefix = "PostConfirmation_"

// Trigger sources sent to the PostConfirmation trigger.
const (
	// TriggerConfirmSignUp follows ConfirmSignUp and AdminConfirmSignUp, and
	// a federated user's first sign-in.
	TriggerConfirmSignUp = "PostConfirmation_ConfirmSignUp"
	// TriggerConfirmForgotPassword follows a forgotten-password reset.
	TriggerConfirmForgotPassword = "PostConfirmation_ConfirmForgotPassword"
)

// Policy actions.
const (
	ActionScramble = "scramble"
	ActionSkip     = "skip"
)

// PasswordLength is the length of the random password set on each user. A
// user pool's minimum password length can be up to 99, and Cognito accepts
// passwords of up to 256 characters.
const PasswordLength = 128

// UserStatusExternalProvider is the cognito:user_status of federated users.
const UserStatusExternalProvider = "EXTERNAL_PROVIDER"

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

// Decision is the policy's result document.
type Decision struct {
	Action string `json:"action"`
	// Reason is logged when the user is skipped.
	Reason string `json:"reason,omitempty"`
}

// Decide evaluates the policy for one input and validates the result.
func Decide(ctx context.Context, p *policy.Engine, in PolicyInput) (*Decision, error) {
	d, err := policy.Eval[Decision](ctx, p, in)
	if err != nil {
		return nil, err
	}
	d.Action = strings.ToLower(strings.TrimSpace(d.Action))
	switch d.Action {
	case ActionScramble, ActionSkip:
		return &d, nil
	case "":
		return nil, errors.New(`policy result has no "action"`)
	default:
		return nil, fmt.Errorf(`policy result has unknown action %q: must be "scramble" or "skip"`, d.Action)
	}
}

// Config configures the hook.
type Config struct {
	Cognito CognitoAPI
	// Policy can exempt users. Nil scrambles every native user's password.
	Policy *policy.Engine
}

// Hook handles PostConfirmation events.
type Hook struct {
	cognito CognitoAPI
	policy  *policy.Engine
}

// New returns the hook.
func New(cfg Config) (*Hook, error) {
	if cfg.Cognito == nil {
		return nil, errors.New("postconfirmation: a cognito client is required")
	}
	return &Hook{cognito: cfg.Cognito, policy: cfg.Policy}, nil
}

// Handle scrambles the user's password unless the user is federated or the
// policy skips them. It never returns an error: Cognito has already confirmed
// the user, so failing would show the user an error without undoing anything.
// Failures are logged as "password scramble failed".
func (h *Hook) Handle(ctx context.Context, e *Event) error {
	ctx = logging.WithAttrs(ctx, slog.String("sub", e.Request.UserAttributes["sub"]))

	if e.Request.UserAttributes["cognito:user_status"] == UserStatusExternalProvider {
		slog.InfoContext(ctx, "password scramble skipped", "reason", "federated user")
		return nil
	}

	if skip, reason := h.skip(ctx, e); skip {
		slog.InfoContext(ctx, "password scramble skipped", "reason", reason)
		return nil
	}

	pw, err := password.Generate(PasswordLength)
	if err != nil {
		slog.ErrorContext(ctx, "password scramble failed", "error", err)
		return nil
	}
	if _, err := h.cognito.AdminSetUserPassword(ctx, &cip.AdminSetUserPasswordInput{
		UserPoolId: aws.String(e.UserPoolID),
		Username:   aws.String(e.UserName),
		Password:   aws.String(pw),
		Permanent:  true,
	}); err != nil {
		slog.ErrorContext(ctx, "password scramble failed", "error", err)
		return nil
	}

	slog.InfoContext(ctx, "password scrambled")
	return nil
}

// skip reports whether the policy exempts the user. It fails closed: when the
// policy fails, the password is scrambled.
func (h *Hook) skip(ctx context.Context, e *Event) (bool, string) {
	if h.policy == nil {
		return false, ""
	}
	d, err := Decide(ctx, h.policy, NewPolicyInput(e))
	if err != nil {
		slog.ErrorContext(ctx, "policy failed, scrambling the password anyway", "error", err)
		return false, ""
	}
	return d.Action == ActionSkip, d.Reason
}
