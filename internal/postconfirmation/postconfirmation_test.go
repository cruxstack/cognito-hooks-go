package postconfirmation

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"

	"github.com/cruxstack/cognito-hooks-go/internal/policy"
)

type fakeCognito struct {
	mu    sync.Mutex
	calls []*cip.AdminSetUserPasswordInput
	err   error
}

func (f *fakeCognito) AdminSetUserPassword(_ context.Context, in *cip.AdminSetUserPasswordInput, _ ...func(*cip.Options)) (*cip.AdminSetUserPasswordOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, in)
	return &cip.AdminSetUserPasswordOutput{}, f.err
}

func compile(t *testing.T, src string) *policy.Engine {
	t.Helper()
	p, err := policy.Compile(context.Background(), "test.rego", "package cognito_hook_postconfirmation\n\n"+src, PolicyQuery)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func event(trigger, status string) *Event {
	e := &Event{}
	e.TriggerSource = trigger
	e.UserPoolID = "us-east-1_EXAMPLE"
	e.UserName = "8a1b2c3d-0000-4000-8000-000000000001"
	e.CallerContext.ClientID = "web"
	e.Request.UserAttributes = map[string]string{
		"sub":                 "8a1b2c3d-0000-4000-8000-000000000001",
		"email":               "user@example.com",
		"cognito:user_status": status,
	}
	return e
}

func newHook(t *testing.T, c *fakeCognito, pol *policy.Engine) *Hook {
	t.Helper()
	h, err := New(Config{Cognito: c, Policy: pol})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHandle_ReplacesPassword(t *testing.T) {
	for _, trigger := range []string{TriggerConfirmSignUp, TriggerConfirmForgotPassword} {
		t.Run(trigger, func(t *testing.T) {
			c := &fakeCognito{}
			if err := newHook(t, c, nil).Handle(context.Background(), event(trigger, "CONFIRMED")); err != nil {
				t.Fatal(err)
			}
			if len(c.calls) != 1 {
				t.Fatalf("AdminSetUserPassword calls = %d, want 1", len(c.calls))
			}
			in := c.calls[0]
			if aws.ToString(in.UserPoolId) != "us-east-1_EXAMPLE" || aws.ToString(in.Username) != "8a1b2c3d-0000-4000-8000-000000000001" {
				t.Errorf("target = %s/%s", aws.ToString(in.UserPoolId), aws.ToString(in.Username))
			}
			if !in.Permanent {
				t.Error("password must be permanent")
			}
			if n := len(aws.ToString(in.Password)); n != PasswordLength {
				t.Errorf("password length = %d, want %d", n, PasswordLength)
			}
		})
	}
}

func TestHandle_EachUserGetsADifferentPassword(t *testing.T) {
	c := &fakeCognito{}
	h := newHook(t, c, nil)
	for range 2 {
		_ = h.Handle(context.Background(), event(TriggerConfirmSignUp, "CONFIRMED"))
	}
	if aws.ToString(c.calls[0].Password) == aws.ToString(c.calls[1].Password) {
		t.Error("two users got the same password")
	}
}

func TestHandle_SkipsFederatedUsers(t *testing.T) {
	c := &fakeCognito{}
	if err := newHook(t, c, nil).Handle(context.Background(), event(TriggerConfirmSignUp, UserStatusExternalProvider)); err != nil {
		t.Fatal(err)
	}
	if len(c.calls) != 0 {
		t.Errorf("AdminSetUserPassword calls = %d, want 0", len(c.calls))
	}
}

func TestHandle_Policy(t *testing.T) {
	tests := map[string]struct {
		policy    string
		wantCalls int
	}{
		"skip":                       {`result := {"actions": [{"action": "password.skip", "reason": "test client"}]} if input.callerContext.clientId == "web"`, 0},
		"replace":                    {`result := {"actions": ["password.replace"]}`, 1},
		"no actions replaces":        {`result := {"actions": []}`, 1},
		"replace wins over skip":     {`result := {"actions": ["password.skip", "password.replace"]}`, 1},
		"names are case insensitive": {`result := {"actions": ["Password.Skip"]}`, 0},
		"undefined replaces":         {`result := {"actions": ["password.skip"]} if input.never`, 1},
		"unknown action replaces":    {`result := {"actions": ["password.keep"]}`, 1},
		"another hook's action":      {`result := {"actions": ["password.skip", "signup.allow"]}`, 1},
		"v0 result replaces":         {`result := {"action": "skip"}`, 1},
		"error replaces":             {"result := {\"actions\": [\"password.skip\"]}\nresult := {\"actions\": []} if true", 1},
		"by trigger":                 {`result := {"actions": ["password.skip"]} if input.trigger == "PostConfirmation_ConfirmSignUp"`, 0},
		"by user attribute":          {`result := {"actions": ["password.skip"]} if endswith(input.userAttributes.email, "@example.com")`, 0},
		"set of actions":             {"result := {\"actions\": actions}\n\nactions contains \"password.skip\" if input.callerContext.clientId == \"web\"", 0},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c := &fakeCognito{}
			if err := newHook(t, c, compile(t, tt.policy)).Handle(context.Background(), event(TriggerConfirmSignUp, "CONFIRMED")); err != nil {
				t.Fatal(err)
			}
			if len(c.calls) != tt.wantCalls {
				t.Errorf("AdminSetUserPassword calls = %d, want %d", len(c.calls), tt.wantCalls)
			}
		})
	}
}

// The policy runs for federated users too, so future actions can apply to
// them, but their password is never replaced: they have none.
func TestHandle_FederatedUsersRunThePolicyButKeepTheirPassword(t *testing.T) {
	c := &fakeCognito{}
	pol := compile(t, `result := {"actions": ["password.replace"]}`)
	if err := newHook(t, c, pol).Handle(context.Background(), event(TriggerConfirmSignUp, UserStatusExternalProvider)); err != nil {
		t.Fatal(err)
	}
	if len(c.calls) != 0 {
		t.Errorf("AdminSetUserPassword calls = %d, want 0", len(c.calls))
	}
}

// Cognito has already confirmed the user, so a failure is logged, not
// returned.
func TestHandle_CognitoErrorDoesNotFail(t *testing.T) {
	c := &fakeCognito{err: errors.New("TooManyRequestsException")}
	if err := newHook(t, c, nil).Handle(context.Background(), event(TriggerConfirmSignUp, "CONFIRMED")); err != nil {
		t.Errorf("Handle() = %v, want nil", err)
	}
	if len(c.calls) != 1 {
		t.Errorf("AdminSetUserPassword calls = %d, want 1", len(c.calls))
	}
}

type fakeStore struct {
	records map[string]time.Time
	err     error
}

func (s *fakeStore) LastReplaced(context.Context, string) (*time.Time, error) { return nil, nil }

func (s *fakeStore) Record(_ context.Context, sub string, t time.Time) error {
	if s.err != nil {
		return s.err
	}
	s.records[sub] = t
	return nil
}

// With a rotation table, each replacement is recorded so the
// PreAuthentication hook doesn't replace the password again.
func TestHandle_RecordsReplacements(t *testing.T) {
	tests := map[string]struct {
		status     string
		cognitoErr error
		policy     string
		want       bool
	}{
		"replaced":       {"CONFIRMED", nil, "", true},
		"federated":      {UserStatusExternalProvider, nil, "", false},
		"skipped":        {"CONFIRMED", nil, `result := {"actions": ["password.skip"]}`, false},
		"failed replace": {"CONFIRMED", errors.New("TooManyRequestsException"), "", false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := &fakeStore{records: map[string]time.Time{}}
			var pol *policy.Engine
			if tt.policy != "" {
				pol = compile(t, tt.policy)
			}
			h, err := New(Config{Cognito: &fakeCognito{err: tt.cognitoErr}, Policy: pol, Rotations: s})
			if err != nil {
				t.Fatal(err)
			}
			before := time.Now()
			if err := h.Handle(context.Background(), event(TriggerConfirmSignUp, tt.status)); err != nil {
				t.Fatal(err)
			}
			at, ok := s.records["8a1b2c3d-0000-4000-8000-000000000001"]
			if ok != tt.want || (ok && at.Before(before)) {
				t.Errorf("record = %v, %v; want recorded = %v", at, ok, tt.want)
			}
		})
	}
}

// The password is already replaced, so a failed write is only logged.
func TestHandle_UnwritableRecordDoesNotFail(t *testing.T) {
	c := &fakeCognito{}
	h, err := New(Config{Cognito: c, Rotations: &fakeStore{err: errors.New("AccessDeniedException")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Handle(context.Background(), event(TriggerConfirmSignUp, "CONFIRMED")); err != nil || len(c.calls) != 1 {
		t.Errorf("Handle() = %v with %d replacements, want nil and 1", err, len(c.calls))
	}
}

func TestDecide(t *testing.T) {
	in := NewPolicyInput(event(TriggerConfirmSignUp, "CONFIRMED"))
	if in.ClientMetadata == nil || in.Trigger != TriggerConfirmSignUp || in.UserPoolID != "us-east-1_EXAMPLE" {
		t.Errorf("input = %+v", in)
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
	if err == nil || !strings.Contains(err.Error(), "password.replace, password.skip") {
		t.Errorf("unknown action: err = %v, want the known actions listed", err)
	}
}

func TestNew_RequiresCognito(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("expected an error without a cognito client")
	}
}
