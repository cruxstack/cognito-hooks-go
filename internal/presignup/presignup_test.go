package presignup

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cruxstack/cognito-hooks-go/internal/policy"
	"github.com/cruxstack/cognito-hooks-go/internal/verify"
)

func compile(t *testing.T, src string) *policy.Engine {
	t.Helper()
	p, err := policy.Compile(context.Background(), "test.rego", "package cognito_hook_presignup\n\n"+src, PolicyQuery)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func event(trigger, email string) *Event {
	e := &Event{}
	e.TriggerSource = trigger
	e.UserPoolID = "us-east-1_EXAMPLE"
	e.Region = "us-east-1"
	e.UserName = "user-1"
	e.CallerContext.ClientID = "web"
	e.Request.UserAttributes = map[string]string{"email": email}
	return e
}

type fakeVerifier struct {
	calls  []string
	result *verify.Result
	err    error
}

func (f *fakeVerifier) Verify(_ context.Context, email string) (*verify.Result, error) {
	f.calls = append(f.calls, email)
	return f.result, f.err
}

func TestDecide(t *testing.T) {
	tests := map[string]struct {
		policy  string
		want    Decision
		wantErr bool
	}{
		"allow with flags": {
			policy: `result := {"action": "allow", "response": {"autoConfirmUser": true, "autoVerifyEmail": true}}`,
			want:   Decision{Action: ActionAllow, Response: &Response{AutoConfirmUser: true, AutoVerifyEmail: true}},
		},
		"allow without a response": {
			policy: `result := {"action": "allow"}`,
			want:   Decision{Action: ActionAllow, Response: &Response{}},
		},
		"deny with a reason": {
			policy: `result := {"action": "deny", "reason": "invite only", "response": {"autoConfirmUser": true}}`,
			want:   Decision{Action: ActionDeny, Reason: "invite only"},
		},
		"deny without a reason": {
			policy: `result := {"action": "deny"}`,
			want:   Decision{Action: ActionDeny, Reason: DefaultDenyReason},
		},
		"action is case insensitive": {
			policy: `result := {"action": " DENY ", "reason": "no"}`,
			want:   Decision{Action: ActionDeny, Reason: "no"},
		},
		"unknown action":   {policy: `result := {"action": "block"}`, wantErr: true},
		"missing action":   {policy: `result := {"reason": "no"}`, wantErr: true},
		"undefined result": {policy: `result := {"action": "allow"} if false`, wantErr: true},
		"not an object":    {policy: `result := "allow"`, wantErr: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d, err := Decide(context.Background(), compile(t, tt.policy), NewPolicyInput(event(TriggerSignUp, "a@example.com"), nil))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Decide() = %+v, want an error", d)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, _ := json.Marshal(d)
			want, _ := json.Marshal(tt.want)
			if string(got) != string(want) {
				t.Errorf("decision = %s, want %s", got, want)
			}
		})
	}
}

func TestHandle_AllowSetsResponse(t *testing.T) {
	h, err := New(Config{Policy: compile(t, `result := {"action": "allow", "response": {"autoConfirmUser": true}}`)})
	if err != nil {
		t.Fatal(err)
	}
	e := event(TriggerSignUp, "a@example.com")
	if err := h.Handle(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if !e.Response.AutoConfirmUser || e.Response.AutoVerifyEmail {
		t.Errorf("response = %+v", e.Response)
	}
}

func TestHandle_DenyReturnsReason(t *testing.T) {
	h, _ := New(Config{Policy: compile(t, `result := {"action": "deny", "reason": "invite only"}`)})
	err := h.Handle(context.Background(), event(TriggerSignUp, "a@example.com"))

	var denied *DeniedError
	if !errors.As(err, &denied) || denied.Error() != "invite only" {
		t.Errorf("err = %v, want a DeniedError with the reason", err)
	}
}

// A broken policy must not let sign-ups through.
func TestHandle_FailsClosed(t *testing.T) {
	for name, src := range map[string]string{
		"conflicting rules": "result := {\"action\": \"allow\"}\nresult := {\"action\": \"deny\"} if true",
		"undefined":         `result := {"action": "deny"} if input.never`,
		"typo in action":    `result := {"action": "alow"}`,
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := New(Config{Policy: compile(t, src)})
			e := event(TriggerSignUp, "a@example.com")
			if err := h.Handle(context.Background(), e); !errors.Is(err, ErrPolicyFailed) {
				t.Errorf("err = %v, want ErrPolicyFailed", err)
			}
		})
	}
}

// echo denies with the policy input as the reason, so tests can inspect it.
const echo = `result := {"action": "deny", "reason": json.marshal(input)}`

func inputOf(t *testing.T, h *Hook, e *Event) map[string]any {
	t.Helper()
	var denied *DeniedError
	if err := h.Handle(context.Background(), e); !errors.As(err, &denied) {
		t.Fatalf("Handle() = %v", err)
	}
	var in map[string]any
	if err := json.Unmarshal([]byte(denied.Reason), &in); err != nil {
		t.Fatal(err)
	}
	return in
}

func TestHandle_PolicyInput(t *testing.T) {
	h, _ := New(Config{Policy: compile(t, echo)})
	e := event(TriggerSignUp, "a@example.com")
	e.Request.ValidationData = map[string]string{"captcha": "token"}

	in := inputOf(t, h, e)
	got, _ := json.Marshal(in)
	want := `{"callerContext":{"awsSdkVersion":"","clientId":"web"},"clientMetadata":{},"region":"us-east-1",` +
		`"trigger":"PreSignUp_SignUp","userAttributes":{"email":"a@example.com"},"userName":"user-1",` +
		`"userPoolId":"us-east-1_EXAMPLE","validationData":{"captcha":"token"}}`
	if string(got) != want {
		t.Errorf("input =\n  %s\nwant\n  %s", got, want)
	}
}

func TestHandle_Verification(t *testing.T) {
	valid := &verify.Result{Provider: verify.ProviderSendGrid, Valid: true, Verdict: verify.VerdictValid, Score: 0.9, Raw: "{}"}

	tests := map[string]struct {
		trigger, email string
		verifier       *fakeVerifier
		wantCalls      int
		wantInput      bool
	}{
		"verified":                 {trigger: TriggerSignUp, email: "a@example.com", verifier: &fakeVerifier{result: valid}, wantCalls: 1, wantInput: true},
		"trigger not listed":       {trigger: TriggerExternalProvider, email: "a@example.com", verifier: &fakeVerifier{result: valid}},
		"no email":                 {trigger: TriggerSignUp, email: "", verifier: &fakeVerifier{result: valid}},
		"verification unavailable": {trigger: TriggerSignUp, email: "a@example.com", verifier: &fakeVerifier{err: errors.New("timeout")}, wantCalls: 1},
		"verification disabled":    {trigger: TriggerSignUp, email: "a@example.com"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := Config{Policy: compile(t, echo), VerifyTriggers: []string{TriggerSignUp}}
			if tt.verifier != nil {
				cfg.Verifier = tt.verifier
			}
			h, _ := New(cfg)

			in := inputOf(t, h, event(tt.trigger, tt.email))
			if _, ok := in["emailVerification"]; ok != tt.wantInput {
				t.Errorf("input has emailVerification = %v, want %v", ok, tt.wantInput)
			}
			if tt.verifier != nil && len(tt.verifier.calls) != tt.wantCalls {
				t.Errorf("verifier called %d times, want %d", len(tt.verifier.calls), tt.wantCalls)
			}
		})
	}
}

func TestNew_RequiresPolicy(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("expected an error without a policy")
	}
}
