// Package preauthentication implements the PreAuthentication hook. It runs
// when a user starts to sign in, and replaces the password of each native,
// confirmed user whose password the hooks haven't replaced since a cutoff
// time with a random one that nobody knows. A password set before the cutoff,
// such as one leaked in a credential-stuffing attack, stops working, while
// users who sign in with passwordless factors such as email one-time
// passwords notice nothing. An optional policy can keep some passwords.
//
// Cognito doesn't record when a password was set, so the hook keeps its own
// record of each replacement (see package rotation).
package preauthentication

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

// PolicyQuery is the rule the optional PreAuthentication policy must define.
const PolicyQuery = "data.cognito_hook_preauthentication.result"

// TriggerPrefix starts every PreAuthentication trigger source.
const TriggerPrefix = "PreAuthentication_"

// TriggerAuthentication is sent when a user starts to sign in with
// InitiateAuth, AdminInitiateAuth, or managed login.
const TriggerAuthentication = "PreAuthentication_Authentication"

// Actions a PreAuthentication policy can return.
const (
	// ActionReplacePassword replaces the user's password with a random one if
	// the hooks haven't replaced it since the cutoff. It is the default when
	// the policy returns no password action, and it wins over
	// ActionSkipPassword.
	ActionReplacePassword = "password.replace"
	// ActionSkipPassword keeps the user's password. It takes an optional
	// "reason", which is logged.
	ActionSkipPassword = "password.skip"
)

// Actions lists the actions a PreAuthentication policy can return.
var Actions = []string{ActionReplacePassword, ActionSkipPassword}

// PasswordLength is the length of the random password set on each user. A
// user pool's minimum password length can be up to 99, and Cognito accepts
// passwords of up to 256 characters.
const PasswordLength = 128

// User statuses whose password the hook never replaces.
const (
	// UserStatusExternalProvider is the cognito:user_status of federated
	// users. Setting a password would turn a federated profile into a
	// password login.
	UserStatusExternalProvider = "EXTERNAL_PROVIDER"
	// UserStatusUnconfirmed is the cognito:user_status of users who haven't
	// confirmed their sign-up. A permanent password would confirm them
	// without verifying their email address.
	UserStatusUnconfirmed = "UNCONFIRMED"
)

// Time limits. Cognito waits at most 5 seconds for the whole function,
// including a cold start, so the hook returns its own error before Cognito
// gives up.
const (
	// Timeout bounds the calls that decide a sign-in: looking up the user,
	// reading the rotation record, and replacing the password.
	Timeout = 3 * time.Second
	// ReadTimeout bounds reading the rotation record, within Timeout, so a
	// slow read leaves time to replace the password.
	ReadTimeout = time.Second
	// WriteTimeout bounds recording a replacement, after Timeout.
	WriteTimeout = 500 * time.Millisecond
)

// UnavailableMessage is the error message Cognito shows the user when the
// hook rejects a sign-in, as "PreAuthentication failed with error
// <message>". The details are logged, not returned.
const UnavailableMessage = "Sign-in is temporarily unavailable. Try again in a moment."

// ErrUnavailable is returned to Cognito, which rejects the sign-in, when the
// hook can't tell whether the password must be replaced or can't replace it.
var ErrUnavailable error = unavailableError{}

// unavailableError carries UnavailableMessage, a sentence for users rather
// than a Go error string.
type unavailableError struct{}

func (unavailableError) Error() string { return UnavailableMessage }

// Event is a PreAuthentication trigger event.
type Event = events.CognitoEventUserPoolsPreAuthentication

// CognitoAPI is the part of the Cognito API the hook calls.
type CognitoAPI interface {
	AdminGetUser(ctx context.Context, params *cip.AdminGetUserInput, optFns ...func(*cip.Options)) (*cip.AdminGetUserOutput, error)
	AdminSetUserPassword(ctx context.Context, params *cip.AdminSetUserPasswordInput, optFns ...func(*cip.Options)) (*cip.AdminSetUserPasswordOutput, error)
}

// PolicyInput is the policy's input document.
type PolicyInput struct {
	cognito.Header
	UserAttributes map[string]string `json:"userAttributes"`
	// ValidationData holds the ClientMetadata of the InitiateAuth or
	// AdminInitiateAuth request.
	ValidationData map[string]string `json:"validationData"`
	// UserNotFound is true for a username that doesn't exist, when the app
	// client prevents user existence errors.
	UserNotFound bool `json:"userNotFound"`
	// PasswordReplacedAt is when the hooks last replaced the password. It is
	// null when they never did, when the record couldn't be read, and for
	// users whose password the hook never replaces.
	PasswordReplacedAt *time.Time `json:"passwordReplacedAt"`
}

// NewPolicyInput builds the policy input for an event and the time of the
// user's last replacement, if any.
func NewPolicyInput(e *Event, replacedAt *time.Time) PolicyInput {
	return PolicyInput{
		Header:             cognito.NewHeader(e.CognitoEventUserPoolsHeader),
		UserAttributes:     cognito.Map(e.Request.UserAttributes),
		ValidationData:     cognito.Map(e.Request.ValidationData),
		UserNotFound:       e.Request.UserNotFound,
		PasswordReplacedAt: replacedAt,
	}
}

// Decision is what the hook does for a user, resolved from the policy's
// actions.
type Decision struct {
	// Actions are the actions the policy returned; empty without a policy.
	Actions []action.Action `json:"actions"`
	// ReplacePassword is false when the password is kept. When it is true,
	// the password is replaced only if it is stale.
	ReplacePassword bool `json:"replacePassword"`
	// Reason is why the password is kept.
	Reason string `json:"reason,omitempty"`
}

// DefaultDecision is the decision without a policy, and when the policy
// fails: replace the password if it is stale.
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
			err = action.Unknown(a, "PreAuthentication", Actions)
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

// SkipReason returns why the hook keeps a user's password whatever the
// policy decides, or "" when it may replace it: the user doesn't exist, is
// federated, or hasn't confirmed their sign-up.
func SkipReason(userNotFound bool, status string) string {
	switch {
	case userNotFound:
		return "user not found"
	case status == UserStatusExternalProvider:
		return "federated user"
	case status == UserStatusUnconfirmed:
		return "unconfirmed user"
	}
	return ""
}

// IsStale reports whether a password last replaced at replacedAt (nil for
// never) must be replaced for the cutoff rotateBefore.
func IsStale(replacedAt *time.Time, rotateBefore time.Time) bool {
	return replacedAt == nil || replacedAt.Before(rotateBefore)
}

// Config configures the hook.
type Config struct {
	Cognito CognitoAPI
	// Rotations records when each password was replaced.
	Rotations rotation.Store
	// RotateBefore is the cutoff: a password the hooks haven't replaced since
	// this time is replaced at the user's next sign-in.
	RotateBefore time.Time
	// Policy decides the actions for each user. Without one, every native,
	// confirmed user's stale password is replaced.
	Policy *policy.Engine
}

// Hook handles PreAuthentication events.
type Hook struct {
	cognito      CognitoAPI
	rotations    rotation.Store
	rotateBefore time.Time
	policy       *policy.Engine

	timeout, readTimeout, writeTimeout time.Duration
}

// New returns the hook.
func New(cfg Config) (*Hook, error) {
	switch {
	case cfg.Cognito == nil:
		return nil, errors.New("preauthentication: a cognito client is required")
	case cfg.Rotations == nil:
		return nil, errors.New("preauthentication: a rotation store is required")
	case cfg.RotateBefore.IsZero():
		return nil, errors.New("preauthentication: a rotation cutoff is required")
	}
	return &Hook{
		cognito:      cfg.Cognito,
		rotations:    cfg.Rotations,
		rotateBefore: cfg.RotateBefore,
		policy:       cfg.Policy,
		timeout:      Timeout,
		readTimeout:  ReadTimeout,
		writeTimeout: WriteTimeout,
	}, nil
}

// user is what the hook needs to know about the user who is signing in.
type user struct {
	sub    string
	status string
}

// Handle replaces the user's password if it is stale, and leaves the event
// unchanged. It fails closed: when it can't tell whether the user may have a
// stale password, or can't replace it, it returns ErrUnavailable and Cognito
// rejects the sign-in, so an old password is never checked. A failure to
// read the rotation record replaces the password, and a failure to record a
// replacement is logged; the next sign-in then replaces it again.
func (h *Hook) Handle(ctx context.Context, e *Event) error {
	// the calls that decide the sign-in share one deadline
	callCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	u, err := h.user(callCtx, e)
	ctx = logging.WithAttrs(ctx, slog.String("sub", u.sub))
	if err != nil {
		slog.ErrorContext(ctx, "user lookup failed", "error", err)
		return ErrUnavailable
	}

	skip := SkipReason(e.Request.UserNotFound, u.status)

	var replacedAt *time.Time
	stale := true
	if skip == "" {
		readCtx, cancelRead := context.WithTimeout(callCtx, h.readTimeout)
		replacedAt, err = h.rotations.LastReplaced(readCtx, u.sub)
		cancelRead()
		if err != nil {
			slog.WarnContext(ctx, "rotation record unavailable, treating the password as stale", "error", err)
		} else {
			stale = IsStale(replacedAt, h.rotateBefore)
		}
	}

	d := h.decide(ctx, NewPolicyInput(e, replacedAt))

	switch {
	case skip != "":
		slog.InfoContext(ctx, "password replacement skipped", "reason", skip)
	case !d.ReplacePassword:
		slog.InfoContext(ctx, "password replacement skipped", "reason", d.Reason)
	case !stale:
		slog.InfoContext(ctx, "password already replaced", "replaced_at", replacedAt.UTC().Format(time.RFC3339))
	default:
		if err := h.replacePassword(callCtx, e); err != nil {
			slog.ErrorContext(ctx, "password replacement failed", "error", err)
			return ErrUnavailable
		}
		slog.InfoContext(ctx, "password replaced")
		h.record(ctx, u.sub)
	}
	return nil
}

// user returns the user's sub and status from the event. When the event
// lacks either, it looks the user up instead of guessing, since replacing
// the password of a federated or unconfirmed user changes how they sign in.
func (h *Hook) user(ctx context.Context, e *Event) (user, error) {
	attrs := e.Request.UserAttributes
	u := user{sub: attrs["sub"], status: attrs["cognito:user_status"]}
	if e.Request.UserNotFound || (u.sub != "" && u.status != "") {
		return u, nil
	}

	out, err := h.cognito.AdminGetUser(ctx, &cip.AdminGetUserInput{
		UserPoolId: aws.String(e.UserPoolID),
		Username:   aws.String(e.UserName),
	})
	if err != nil {
		return u, err
	}
	for _, a := range out.UserAttributes {
		if aws.ToString(a.Name) == "sub" {
			u.sub = aws.ToString(a.Value)
		}
	}
	if u.status = string(out.UserStatus); u.status == "" {
		return u, errors.New("AdminGetUser returned no user status")
	}
	return u, nil
}

// decide returns the policy's decision, or the default decision when there
// is no policy or it fails.
func (h *Hook) decide(ctx context.Context, in PolicyInput) *Decision {
	if h.policy == nil {
		return DefaultDecision()
	}
	d, err := Decide(ctx, h.policy, in)
	if err != nil {
		slog.ErrorContext(ctx, "policy failed, applying the default actions", "error", err)
		return DefaultDecision()
	}
	return d
}

func (h *Hook) replacePassword(ctx context.Context, e *Event) error {
	pw, err := password.Generate(PasswordLength)
	if err != nil {
		return err
	}
	_, err = h.cognito.AdminSetUserPassword(ctx, &cip.AdminSetUserPasswordInput{
		UserPoolId: aws.String(e.UserPoolID),
		Username:   aws.String(e.UserName),
		Password:   aws.String(pw),
		Permanent:  true,
	})
	return err
}

// record records a replacement. The password is already replaced, so a
// failure is logged and the sign-in continues; the next sign-in replaces the
// password again.
func (h *Hook) record(ctx context.Context, sub string) {
	writeCtx, cancel := context.WithTimeout(ctx, h.writeTimeout)
	defer cancel()
	if err := h.rotations.Record(writeCtx, sub, time.Now()); err != nil {
		slog.ErrorContext(ctx, "password replacement not recorded", "error", err)
	}
}
