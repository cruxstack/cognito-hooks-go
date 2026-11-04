package preauthentication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"

	"github.com/cruxstack/cognito-hooks-go/internal/logging"
	"github.com/cruxstack/cognito-hooks-go/internal/policy"
)

const sub = "8a1b2c3d-0000-4000-8000-000000000001"

var cutoff = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

type fakeCognito struct {
	mu       sync.Mutex
	set      []*cip.AdminSetUserPasswordInput
	get      []*cip.AdminGetUserInput
	user     *cip.AdminGetUserOutput
	getErr   error
	setErr   error
	setBlock bool // wait for the context to end
}

func (f *fakeCognito) AdminGetUser(_ context.Context, in *cip.AdminGetUserInput, _ ...func(*cip.Options)) (*cip.AdminGetUserOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.get = append(f.get, in)
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.user, nil
}

func (f *fakeCognito) AdminSetUserPassword(ctx context.Context, in *cip.AdminSetUserPasswordInput, _ ...func(*cip.Options)) (*cip.AdminSetUserPasswordOutput, error) {
	f.mu.Lock()
	f.set = append(f.set, in)
	block, err := f.setBlock, f.setErr
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return &cip.AdminSetUserPasswordOutput{}, nil
}

type fakeStore struct {
	mu        sync.Mutex
	records   map[string]time.Time
	reads     int
	readErr   error
	writeErr  error
	readBlock bool // wait for the context to end
}

func newStore() *fakeStore { return &fakeStore{records: map[string]time.Time{}} }

func (s *fakeStore) LastReplaced(ctx context.Context, sub string) (*time.Time, error) {
	s.mu.Lock()
	s.reads++
	block, err := s.readBlock, s.readErr
	t, ok := s.records[sub]
	s.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return &t, nil
}

func (s *fakeStore) Record(_ context.Context, sub string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return s.writeErr
	}
	s.records[sub] = t
	return nil
}

func (s *fakeStore) recorded(sub string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.records[sub]
	return t, ok
}

func compile(t *testing.T, src string) *policy.Engine {
	t.Helper()
	p, err := policy.Compile(context.Background(), "test.rego", "package cognito_hook_preauthentication\n\n"+src, PolicyQuery)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func event(status string) *Event {
	e := &Event{}
	e.TriggerSource = TriggerAuthentication
	e.UserPoolID = "us-east-1_EXAMPLE"
	e.UserName = sub
	e.CallerContext.ClientID = "web"
	e.Request.UserAttributes = map[string]string{
		"sub":                 sub,
		"email":               "user@example.com",
		"cognito:user_status": status,
	}
	return e
}

// newHook returns the hook with password rotation enabled.
func newHook(t *testing.T, c *fakeCognito, s *fakeStore, pol *policy.Engine) *Hook {
	t.Helper()
	h, err := New(Config{
		Policy:           pol,
		PasswordRotation: &PasswordRotation{Cognito: c, Rotations: s, RotateBefore: cutoff},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// Password rotation is off unless configured: the hook evaluates the policy,
// leaves the event unchanged, and has no Cognito or DynamoDB client to call,
// even for a confirmed user who never had a replacement.
func TestHandle_WithoutPasswordRotation(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(logging.NewJSONHandler(&logs, slog.LevelDebug)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	for name, pol := range map[string]*policy.Engine{
		"no policy":     nil,
		"replace":       compile(t, `result := {"actions": ["password.replace"]}`),
		"skip":          compile(t, `result := {"actions": ["password.skip"]}`),
		"broken policy": compile(t, `result := "skip"`),
	} {
		t.Run(name, func(t *testing.T) {
			logs.Reset()
			h, err := New(Config{Policy: pol})
			if err != nil {
				t.Fatal(err)
			}
			e := event("CONFIRMED")
			want, _ := json.Marshal(e)
			if err := h.Handle(context.Background(), e); err != nil {
				t.Fatalf("Handle() = %v, want nil", err)
			}
			if got, _ := json.Marshal(e); !bytes.Equal(got, want) {
				t.Errorf("event changed:\n  %s\nwant\n  %s", got, want)
			}
			for _, msg := range []string{"password replace", "password already", "rotation record", "user lookup"} {
				if strings.Contains(logs.String(), msg) {
					t.Errorf("logs = %s, want no password rotation", logs.String())
				}
			}
		})
	}
}

func TestHandle_ReplacesAndRecords(t *testing.T) {
	c, s := &fakeCognito{}, newStore()
	before := time.Now()
	e := event("CONFIRMED")
	want, _ := json.Marshal(e)

	if err := newHook(t, c, s, nil).Handle(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if len(c.set) != 1 {
		t.Fatalf("AdminSetUserPassword calls = %d, want 1", len(c.set))
	}
	in := c.set[0]
	if aws.ToString(in.UserPoolId) != "us-east-1_EXAMPLE" || aws.ToString(in.Username) != sub {
		t.Errorf("target = %s/%s", aws.ToString(in.UserPoolId), aws.ToString(in.Username))
	}
	if !in.Permanent {
		t.Error("password must be permanent")
	}
	if n := len(aws.ToString(in.Password)); n != PasswordLength {
		t.Errorf("password length = %d, want %d", n, PasswordLength)
	}
	if at, ok := s.recorded(sub); !ok || at.Before(before) {
		t.Errorf("record = %v, %v; want the time of the replacement", at, ok)
	}
	if got, _ := json.Marshal(e); !bytes.Equal(got, want) {
		t.Errorf("event changed:\n  %s\nwant\n  %s", got, want)
	}
	if len(c.get) != 0 {
		t.Errorf("AdminGetUser calls = %d, want 0: the event has the status", len(c.get))
	}
}

func TestHandle_ReplacesOnlyStalePasswords(t *testing.T) {
	tests := map[string]struct {
		record    *time.Time
		wantCalls int
	}{
		"never replaced":         {nil, 1},
		"replaced before cutoff": {aws.Time(cutoff.Add(-time.Second)), 1},
		"replaced at cutoff":     {aws.Time(cutoff), 0},
		"replaced after cutoff":  {aws.Time(cutoff.Add(time.Hour)), 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c, s := &fakeCognito{}, newStore()
			if tt.record != nil {
				s.records[sub] = *tt.record
			}
			if err := newHook(t, c, s, nil).Handle(context.Background(), event("CONFIRMED")); err != nil {
				t.Fatal(err)
			}
			if len(c.set) != tt.wantCalls {
				t.Errorf("AdminSetUserPassword calls = %d, want %d", len(c.set), tt.wantCalls)
			}
		})
	}
}

// A user who signs in again after a replacement keeps the new password.
func TestHandle_SecondSignInKeepsTheNewPassword(t *testing.T) {
	c, s := &fakeCognito{}, newStore()
	h := newHook(t, c, s, nil)
	for range 2 {
		if err := h.Handle(context.Background(), event("CONFIRMED")); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.set) != 1 {
		t.Errorf("AdminSetUserPassword calls = %d, want 1", len(c.set))
	}
}

func TestHandle_SkipsUsersWithoutAReplaceablePassword(t *testing.T) {
	notFound := event("")
	notFound.Request.UserAttributes = map[string]string{}
	notFound.Request.UserNotFound = true

	tests := map[string]*Event{
		"user not found":   notFound,
		"federated user":   event(UserStatusExternalProvider),
		"unconfirmed user": event(UserStatusUnconfirmed),
	}
	for name, e := range tests {
		t.Run(name, func(t *testing.T) {
			c, s := &fakeCognito{}, newStore()
			// the policy asks for a replacement, but these users never get one
			pol := compile(t, `result := {"actions": ["password.replace"]}`)
			if err := newHook(t, c, s, pol).Handle(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			if len(c.set) != 0 || len(c.get) != 0 || s.reads != 0 {
				t.Errorf("calls: AdminSetUserPassword %d, AdminGetUser %d, record reads %d; want none", len(c.set), len(c.get), s.reads)
			}
		})
	}
}

// Other statuses, such as FORCE_CHANGE_PASSWORD and RESET_REQUIRED, have a
// password that someone may know.
func TestHandle_ReplacesOtherStatuses(t *testing.T) {
	for _, status := range []string{"CONFIRMED", "FORCE_CHANGE_PASSWORD", "RESET_REQUIRED"} {
		c := &fakeCognito{}
		if err := newHook(t, c, newStore(), nil).Handle(context.Background(), event(status)); err != nil {
			t.Fatal(err)
		}
		if len(c.set) != 1 {
			t.Errorf("%s: AdminSetUserPassword calls = %d, want 1", status, len(c.set))
		}
	}
}

func TestHandle_Policy(t *testing.T) {
	tests := map[string]struct {
		policy    string
		wantCalls int
	}{
		"skip":                       {`result := {"actions": [{"action": "password.skip", "reason": "e2e user"}]} if input.userName == "8a1b2c3d-0000-4000-8000-000000000001"`, 0},
		"replace":                    {`result := {"actions": ["password.replace"]}`, 1},
		"no actions replaces":        {`result := {"actions": []}`, 1},
		"replace wins over skip":     {`result := {"actions": ["password.skip", "password.replace"]}`, 1},
		"names are case insensitive": {`result := {"actions": ["Password.Skip"]}`, 0},
		"undefined replaces":         {`result := {"actions": ["password.skip"]} if input.never`, 1},
		"unknown action replaces":    {`result := {"actions": ["password.keep"]}`, 1},
		"unknown parameter replaces": {`result := {"actions": [{"action": "password.skip", "until": "tomorrow"}]}`, 1},
		"another hook's action":      {`result := {"actions": ["password.skip", "signup.allow"]}`, 1},
		"v0 result replaces":         {`result := {"action": "skip"}`, 1},
		"error replaces":             {"result := {\"actions\": [\"password.skip\"]}\nresult := {\"actions\": []} if true", 1},
		"by sub":                     {`result := {"actions": ["password.skip"]} if input.userAttributes.sub == "8a1b2c3d-0000-4000-8000-000000000001"`, 0},
		"by validation data":         {`result := {"actions": ["password.skip"]} if input.validationData.suite == "e2e"`, 0},
		"by record":                  {`result := {"actions": ["password.skip"]} if input.passwordReplacedAt == null`, 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := &fakeCognito{}
			e := event("CONFIRMED")
			e.Request.ValidationData = map[string]string{"suite": "e2e"}
			if err := newHook(t, c, newStore(), compile(t, tt.policy)).Handle(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			if len(c.set) != tt.wantCalls {
				t.Errorf("AdminSetUserPassword calls = %d, want %d", len(c.set), tt.wantCalls)
			}
		})
	}
}

// password.replace doesn't replace a password that is already current.
func TestHandle_PolicyReplaceKeepsACurrentPassword(t *testing.T) {
	c, s := &fakeCognito{}, newStore()
	s.records[sub] = cutoff.Add(time.Hour)
	pol := compile(t, `result := {"actions": ["password.replace"]}`)
	if err := newHook(t, c, s, pol).Handle(context.Background(), event("CONFIRMED")); err != nil {
		t.Fatal(err)
	}
	if len(c.set) != 0 {
		t.Errorf("AdminSetUserPassword calls = %d, want 0", len(c.set))
	}
}

func TestHandle_PolicySeesTheRecord(t *testing.T) {
	s := newStore()
	s.records[sub] = time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	// keep passwords replaced since October, before the cutoff
	pol := compile(t, `result := {"actions": ["password.skip"]} if time.parse_rfc3339_ns(input.passwordReplacedAt) >= time.parse_rfc3339_ns("2026-10-01T00:00:00Z")`)
	c := &fakeCognito{}
	if err := newHook(t, c, s, pol).Handle(context.Background(), event("CONFIRMED")); err != nil {
		t.Fatal(err)
	}
	if len(c.set) != 0 {
		t.Errorf("AdminSetUserPassword calls = %d, want 0", len(c.set))
	}
}

// A missing status is looked up rather than guessed.
func TestHandle_LooksUpAMissingStatus(t *testing.T) {
	tests := map[string]struct {
		status    types.UserStatusType
		wantCalls int
	}{
		"confirmed":   {types.UserStatusTypeConfirmed, 1},
		"federated":   {types.UserStatusTypeExternalProvider, 0},
		"unconfirmed": {types.UserStatusTypeUnconfirmed, 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := &fakeCognito{user: &cip.AdminGetUserOutput{
				UserStatus:     tt.status,
				UserAttributes: []types.AttributeType{{Name: aws.String("sub"), Value: aws.String(sub)}},
			}}
			s := newStore()
			e := event("")
			e.Request.UserAttributes = map[string]string{"email": "user@example.com"}

			if err := newHook(t, c, s, nil).Handle(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			if len(c.get) != 1 || aws.ToString(c.get[0].Username) != sub || aws.ToString(c.get[0].UserPoolId) != "us-east-1_EXAMPLE" {
				t.Fatalf("AdminGetUser calls = %+v, want one for the user", c.get)
			}
			if len(c.set) != tt.wantCalls {
				t.Errorf("AdminSetUserPassword calls = %d, want %d", len(c.set), tt.wantCalls)
			}
			if _, ok := s.recorded(sub); ok != (tt.wantCalls == 1) {
				t.Errorf("recorded = %v, want the looked-up sub recorded only after a replacement", ok)
			}
		})
	}
}

func TestHandle_FailsClosed(t *testing.T) {
	tests := map[string]struct {
		cognito *fakeCognito
		event   *Event
	}{
		"throttled replacement": {
			cognito: &fakeCognito{setErr: &types.TooManyRequestsException{Message: aws.String("Rate exceeded")}},
			event:   event("CONFIRMED"),
		},
		"failed replacement": {
			cognito: &fakeCognito{setErr: errors.New("InternalErrorException")},
			event:   event("CONFIRMED"),
		},
		"failed lookup": {
			cognito: &fakeCognito{getErr: &types.TooManyRequestsException{Message: aws.String("Rate exceeded")}},
			event:   event(""),
		},
		"lookup without a status": {
			cognito: &fakeCognito{user: &cip.AdminGetUserOutput{}},
			event:   event(""),
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := newStore()
			err := newHook(t, tt.cognito, s, nil).Handle(context.Background(), tt.event)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Handle() = %v, want ErrUnavailable", err)
			}
			if err.Error() != "Sign-in is temporarily unavailable. Try again in a moment." {
				t.Errorf("message = %q, want the generic message for users", err)
			}
			if _, ok := s.recorded(sub); ok {
				t.Error("a failed sign-in must not record a replacement")
			}
		})
	}
}

// Without the record the hook can't know the password is current, so it
// replaces it.
func TestHandle_UnreadableRecordReplaces(t *testing.T) {
	c, s := &fakeCognito{}, newStore()
	s.records[sub] = cutoff.Add(time.Hour)
	s.readErr = errors.New("ProvisionedThroughputExceededException")
	if err := newHook(t, c, s, nil).Handle(context.Background(), event("CONFIRMED")); err != nil {
		t.Fatal(err)
	}
	if len(c.set) != 1 {
		t.Errorf("AdminSetUserPassword calls = %d, want 1", len(c.set))
	}
}

// The password is already replaced, so a failed write doesn't fail the
// sign-in; the next sign-in replaces it again.
func TestHandle_UnwritableRecordAllowsTheSignIn(t *testing.T) {
	c, s := &fakeCognito{}, newStore()
	s.writeErr = errors.New("AccessDeniedException")
	h := newHook(t, c, s, nil)
	for range 2 {
		if err := h.Handle(context.Background(), event("CONFIRMED")); err != nil {
			t.Fatalf("Handle() = %v, want nil", err)
		}
	}
	if len(c.set) != 2 {
		t.Errorf("AdminSetUserPassword calls = %d, want 2", len(c.set))
	}
}

func TestHandle_Deadlines(t *testing.T) {
	t.Run("slow replacement fails before cognito times out", func(t *testing.T) {
		c := &fakeCognito{setBlock: true}
		h := newHook(t, c, newStore(), nil)
		h.timeout = 50 * time.Millisecond

		start := time.Now()
		err := h.Handle(context.Background(), event("CONFIRMED"))
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("Handle() = %v, want ErrUnavailable", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("Handle() took %v, want about the timeout", d)
		}
	})

	t.Run("slow read leaves time to replace", func(t *testing.T) {
		c, s := &fakeCognito{}, newStore()
		s.readBlock = true
		h := newHook(t, c, s, nil)
		h.timeout, h.rotation.readTimeout = time.Second, 20*time.Millisecond

		if err := h.Handle(context.Background(), event("CONFIRMED")); err != nil {
			t.Fatal(err)
		}
		if len(c.set) != 1 {
			t.Errorf("AdminSetUserPassword calls = %d, want 1", len(c.set))
		}
	})
}

// The password is never logged, even at the debug level, or returned.
func TestHandle_PasswordStaysSecret(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(logging.NewJSONHandler(&logs, slog.LevelDebug)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	c := &fakeCognito{}
	h := newHook(t, c, newStore(), nil)
	e := event("CONFIRMED")
	if err := h.Handle(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	pw := aws.ToString(c.set[0].Password)
	resp, _ := json.Marshal(e)
	if strings.Contains(logs.String(), pw) || strings.Contains(string(resp), pw) {
		t.Error("the password appears in the logs or the response")
	}
	if !strings.Contains(logs.String(), `"msg":"password replaced"`) || !strings.Contains(logs.String(), `"sub":"`+sub+`"`) {
		t.Errorf("logs = %s, want the replacement logged with the sub", logs.String())
	}

	// a failed replacement doesn't leak it either
	logs.Reset()
	c.setErr = errors.New("InvalidPasswordException")
	err := newHook(t, c, newStore(), nil).Handle(context.Background(), event("CONFIRMED"))
	pw = aws.ToString(c.set[1].Password)
	if err == nil || strings.Contains(err.Error(), pw) || strings.Contains(logs.String(), pw) {
		t.Error("the password appears in the error or the logs")
	}
	if !strings.Contains(logs.String(), `"msg":"password replacement failed"`) {
		t.Errorf("logs = %s, want password replacement failed", logs.String())
	}
}

func TestDecide(t *testing.T) {
	at := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	e := event("CONFIRMED")
	e.Request.ValidationData = nil
	in := NewPolicyInput(e, &at)
	if in.ValidationData == nil || in.Trigger != TriggerAuthentication || in.UserPoolID != "us-east-1_EXAMPLE" || in.PasswordReplacedAt != &at {
		t.Errorf("input = %+v", in)
	}
	b, _ := json.Marshal(NewPolicyInput(e, nil))
	if !strings.Contains(string(b), `"passwordReplacedAt":null`) || !strings.Contains(string(b), `"userNotFound":false`) {
		t.Errorf("input = %s, want passwordReplacedAt null and userNotFound", b)
	}

	d, err := Decide(context.Background(), compile(t, `result := {"actions": [{"action": "password.skip", "reason": " tester "}]}`), in)
	if err != nil || d.ReplacePassword || d.Reason != "tester" || len(d.Actions) != 1 {
		t.Errorf("Decide() = %+v, %v", d, err)
	}

	d, err = Decide(context.Background(), compile(t, `result := {}`), in)
	if err != nil || !d.ReplacePassword || d.Actions == nil {
		t.Errorf("no actions: Decide() = %+v, %v; want the default", d, err)
	}

	_, err = Decide(context.Background(), compile(t, `result := {"actions": ["groups.add"]}`), in)
	if err == nil || !strings.Contains(err.Error(), "PreAuthentication policies can return password.replace, password.skip") {
		t.Errorf("unknown action: err = %v, want the known actions listed", err)
	}
}

func TestIsStale(t *testing.T) {
	if !IsStale(nil, cutoff) || !IsStale(aws.Time(cutoff.Add(-time.Nanosecond)), cutoff) ||
		IsStale(aws.Time(cutoff), cutoff) || IsStale(aws.Time(cutoff.Add(time.Hour)), cutoff) {
		t.Error("a password is stale when it was never replaced or was replaced before the cutoff")
	}
}

func TestNew(t *testing.T) {
	if _, err := New(Config{}); err != nil {
		t.Errorf("New() without features = %v, want the hook", err)
	}
	for name, r := range map[string]PasswordRotation{
		"cognito":   {Rotations: newStore(), RotateBefore: cutoff},
		"rotations": {Cognito: &fakeCognito{}, RotateBefore: cutoff},
		"cutoff":    {Cognito: &fakeCognito{}, Rotations: newStore()},
	} {
		if _, err := New(Config{PasswordRotation: &r}); err == nil {
			t.Errorf("expected an error for password rotation without a %s", name)
		}
	}
}
