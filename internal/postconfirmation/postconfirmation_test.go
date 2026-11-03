package postconfirmation

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

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

func TestHandle_Scrambles(t *testing.T) {
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
		"skip":                {`result := {"action": "skip", "reason": "test client"} if input.callerContext.clientId == "web"`, 0},
		"scramble":            {`result := {"action": "scramble"}`, 1},
		"action is any case":  {`result := {"action": "Skip"}`, 0},
		"undefined scrambles": {`result := {"action": "skip"} if input.never`, 1},
		"invalid scrambles":   {`result := {"action": "skipp"}`, 1},
		"error scrambles":     {"result := {\"action\": \"skip\"}\nresult := {\"action\": \"scramble\"} if true", 1},
		"by trigger":          {`result := {"action": "skip"} if input.trigger == "PostConfirmation_ConfirmSignUp"`, 0},
		"by user attribute":   {`result := {"action": "skip"} if endswith(input.userAttributes.email, "@example.com")`, 0},
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

func TestDecide(t *testing.T) {
	in := NewPolicyInput(event(TriggerConfirmSignUp, "CONFIRMED"))
	if in.ClientMetadata == nil || in.Trigger != TriggerConfirmSignUp || in.UserPoolID != "us-east-1_EXAMPLE" {
		t.Errorf("input = %+v", in)
	}

	d, err := Decide(context.Background(), compile(t, `result := {"action": "skip", "reason": "tester"}`), in)
	if err != nil || d.Action != ActionSkip || d.Reason != "tester" {
		t.Errorf("Decide() = %+v, %v", d, err)
	}

	_, err = Decide(context.Background(), compile(t, `result := {"reason": "x"}`), in)
	if err == nil || !strings.Contains(err.Error(), `no "action"`) {
		t.Errorf("missing action: err = %v", err)
	}
}

func TestNew_RequiresCognito(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("expected an error without a cognito client")
	}
}
