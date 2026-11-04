// Package preauthentication implements the PreAuthentication hook. It runs
// when a user starts to sign in, evaluates its optional policy, and carries
// out the features it has enabled.
//
// Its one feature today, password rotation, is off by default. When enabled,
// it replaces the password of each native, confirmed user whose password the
// hooks haven't replaced since a cutoff time with a random one that nobody
// knows. A password set before the cutoff, such as one leaked in a
// credential-stuffing attack, stops working, while users who sign in with
// passwordless factors such as email one-time passwords notice nothing.
// Cognito doesn't record when a password was set, so rotation keeps its own
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

// Actions a PreAuthentication policy can return. The password actions only
// have an effect when password rotation is enabled.
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
	// Timeout bounds the AWS calls that decide a sign-in, such as password
	// rotation's user lookup, record read, and replacement.
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

// ErrUnavailable is returned to Cognito, which rejects the sign-in, when an
// enabled feature can't do its job, such as password rotation failing to
// tell whether the password must be replaced or to replace it.
var ErrUnavailable error = unavailableError{}

// unavailableError carries UnavailableMessage, a sentence for users rather
// than a Go error string.
type unavailableError struct{}

func (unavailableError) Error() string { return UnavailableMessage }

// Event is a PreAuthentication trigger event.
type Event = events.CognitoEventUserPoolsPreAuthentication

// CognitoAPI is the part of the Cognito API password rotation calls.
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
	// null when they never did, when the record couldn't be read, when
	// password rotation is disabled, and for users whose password the hook
	// never replaces.
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
	// ReplacePassword is false when the password is kept. When it is true
	// and password rotation is enabled, the password is replaced if it is
	// stale.
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

// SkipReason returns why password rotation keeps a user's password whatever
// the policy decides, or "" when it may replace it: the user doesn't exist,
// is federated, or hasn't confirmed their sign-up.
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
	// Policy decides the actions for each user. It is optional.
	Policy *policy.Engine
	// PasswordRotation enables password rotation. Nil disables it, and the
	// hook makes no AWS calls.
	PasswordRotation *PasswordRotation
}

// PasswordRotation configures password rotation.
type PasswordRotation struct {
	Cognito CognitoAPI
	// Rotations records when each password was replaced.
	Rotations rotation.Store
	// RotateBefore is the cutoff: a password the hooks haven't replaced since
	// this time is replaced at the user's next sign-in.
	RotateBefore time.Time
}

// Hook handles PreAuthentication events.
type Hook struct {
	policy  *policy.Engine
	timeout time.Duration
	// rotation is nil when password rotation is disabled.
	rotation *passwordRotation
}

// New returns the hook.
func New(cfg Config) (*Hook, error) {
	h := &Hook{policy: cfg.Policy, timeout: Timeout}
	if r := cfg.PasswordRotation; r != nil {
		switch {
		case r.Cognito == nil:
			return nil, errors.New("preauthentication: password rotation needs a cognito client")
		case r.Rotations == nil:
			return nil, errors.New("preauthentication: password rotation needs a rotation store")
		case r.RotateBefore.IsZero():
			return nil, errors.New("preauthentication: password rotation needs a cutoff")
		}
		h.rotation = &passwordRotation{
			cognito:      r.Cognito,
			rotations:    r.Rotations,
			rotateBefore: r.RotateBefore,
			readTimeout:  ReadTimeout,
			writeTimeout: WriteTimeout,
		}
	}
	return h, nil
}

// Handle evaluates the policy for one sign-in and carries out the enabled
// features, leaving the event unchanged. An enabled feature that can't do
// its job returns ErrUnavailable, and Cognito rejects the sign-in.
func (h *Hook) Handle(ctx context.Context, e *Event) error {
	// the calls that decide the sign-in share one deadline
	callCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	u := user{sub: e.Request.UserAttributes["sub"], status: e.Request.UserAttributes["cognito:user_status"]}
	var err error
	if h.rotation != nil {
		u, err = h.rotation.lookup(callCtx, e, u)
	}
	ctx = logging.WithAttrs(ctx, slog.String("sub", u.sub))
	if err != nil {
		slog.ErrorContext(ctx, "user lookup failed", "error", err)
		return ErrUnavailable
	}

	var pw passwordState
	if h.rotation != nil {
		pw = h.rotation.read(ctx, callCtx, e, u)
	}

	d := h.decide(ctx, NewPolicyInput(e, pw.replacedAt))

	if h.rotation != nil {
		if err := h.rotation.apply(ctx, callCtx, e, u, pw, d); err != nil {
			return ErrUnavailable
		}
	}
	return nil
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

// user is what the hook knows about the user who is signing in.
type user struct {
	sub    string
	status string
}

// passwordRotation replaces stale passwords. It fails closed: when it can't
// tell whether the user may have a stale password, or can't replace it, the
// sign-in is rejected, so an old password is never checked. A failure to
// read the rotation record replaces the password, and a failure to record a
// replacement is logged; the next sign-in then replaces it again.
type passwordRotation struct {
	cognito      CognitoAPI
	rotations    rotation.Store
	rotateBefore time.Time

	readTimeout, writeTimeout time.Duration
}

// passwordState is what password rotation knows before the policy runs.
type passwordState struct {
	// skip is why the password is never replaced, or "".
	skip       string
	replacedAt *time.Time
	stale      bool
}

// lookup completes the user's sub and status. When the event lacks either,
// it looks the user up instead of guessing, since replacing the password of
// a federated or unconfirmed user changes how they sign in.
func (r *passwordRotation) lookup(ctx context.Context, e *Event, u user) (user, error) {
	if e.Request.UserNotFound || (u.sub != "" && u.status != "") {
		return u, nil
	}

	out, err := r.cognito.AdminGetUser(ctx, &cip.AdminGetUserInput{
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

// read reads the user's rotation record, unless the password is never
// replaced. An unreadable record counts as stale.
func (r *passwordRotation) read(ctx, callCtx context.Context, e *Event, u user) passwordState {
	s := passwordState{skip: SkipReason(e.Request.UserNotFound, u.status), stale: true}
	if s.skip != "" {
		return s
	}

	readCtx, cancel := context.WithTimeout(callCtx, r.readTimeout)
	defer cancel()
	t, err := r.rotations.LastReplaced(readCtx, u.sub)
	if err != nil {
		slog.WarnContext(ctx, "rotation record unavailable, treating the password as stale", "error", err)
		return s
	}
	s.replacedAt, s.stale = t, IsStale(t, r.rotateBefore)
	return s
}

// apply replaces a stale password unless the user or the policy keeps it.
func (r *passwordRotation) apply(ctx, callCtx context.Context, e *Event, u user, s passwordState, d *Decision) error {
	switch {
	case s.skip != "":
		slog.InfoContext(ctx, "password replacement skipped", "reason", s.skip)
	case !d.ReplacePassword:
		slog.InfoContext(ctx, "password replacement skipped", "reason", d.Reason)
	case !s.stale:
		slog.InfoContext(ctx, "password already replaced", "replaced_at", s.replacedAt.UTC().Format(time.RFC3339))
	default:
		if err := r.replace(callCtx, e); err != nil {
			slog.ErrorContext(ctx, "password replacement failed", "error", err)
			return err
		}
		slog.InfoContext(ctx, "password replaced")
		r.record(ctx, u.sub)
	}
	return nil
}

func (r *passwordRotation) replace(ctx context.Context, e *Event) error {
	pw, err := password.Generate(PasswordLength)
	if err != nil {
		return err
	}
	_, err = r.cognito.AdminSetUserPassword(ctx, &cip.AdminSetUserPasswordInput{
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
func (r *passwordRotation) record(ctx context.Context, sub string) {
	writeCtx, cancel := context.WithTimeout(ctx, r.writeTimeout)
	defer cancel()
	if err := r.rotations.Record(writeCtx, sub, time.Now()); err != nil {
		slog.ErrorContext(ctx, "password replacement not recorded", "error", err)
	}
}
