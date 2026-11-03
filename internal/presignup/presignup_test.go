package presignup

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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

// outcome summarizes a decision as "allow[:flags]" or "deny:<reason>".
func outcome(d *Decision) string {
	if !d.Allowed {
		return "deny:" + d.Reason
	}
	out := "allow"
	if d.Response.AutoConfirmUser {
		out += ":confirm"
	}
	if d.Response.AutoVerifyEmail {
		out += ":email"
	}
	if d.Response.AutoVerifyPhone {
		out += ":phone"
	}
	return out
}

func TestDecide(t *testing.T) {
	tests := map[string]struct {
		policy string
		want   string // "" means invalid
	}{
		"allow": {
			policy: `result := {"actions": ["signup.allow"]}`,
			want:   "allow",
		},
		"allow with every flag": {
			policy: `result := {"actions": ["signup.allow", "user.confirm", "email.verify", "phone.verify"]}`,
			want:   "allow:confirm:email:phone",
		},
		"deny with a reason": {
			policy: `result := {"actions": [{"action": "signup.deny", "reason": " invite only "}]}`,
			want:   "deny:invite only",
		},
		"deny without a reason": {
			policy: `result := {"actions": ["signup.deny"]}`,
			want:   "deny:" + DefaultDenyReason,
		},
		"deny wins over allow and drops the flags": {
			policy: `result := {"actions": ["signup.allow", "user.confirm", {"action": "signup.deny", "reason": "no"}]}`,
			want:   "deny:no",
		},
		"the first denial's reason is shown": {
			policy: `result := {"actions": [{"action": "signup.deny", "reason": "first"}, {"action": "signup.deny", "reason": "second"}]}`,
			want:   "deny:first",
		},
		"names are case insensitive": {
			policy: `result := {"actions": [" Signup.Allow ", "USER.CONFIRM"]}`,
			want:   "allow:confirm",
		},
		"duplicates are fine": {
			policy: `result := {"actions": ["signup.allow", "signup.allow"]}`,
			want:   "allow",
		},
		"a set of actions": {
			policy: "result := {\"actions\": actions}\n\nactions contains \"signup.allow\"\n\nactions contains \"user.confirm\" if input.trigger == \"PreSignUp_SignUp\"",
			want:   "allow:confirm",
		},
		"flags without a decision":           {policy: `result := {"actions": ["user.confirm"]}`},
		"no actions":                         {policy: `result := {"actions": []}`},
		"another hook's action":              {policy: `result := {"actions": ["signup.allow", "password.replace"]}`},
		"unknown action":                     {policy: `result := {"actions": ["signup.block"]}`},
		"misspelled parameter":               {policy: `result := {"actions": [{"action": "signup.deny", "reson": "no"}]}`},
		"parameter on an action without any": {policy: `result := {"actions": [{"action": "signup.allow", "reason": "yes"}]}`},
		"v0 result":                          {policy: `result := {"action": "allow", "response": {}}`},
		"undefined result":                   {policy: `result := {"actions": ["signup.allow"]} if false`},
		"not an object":                      {policy: `result := "signup.allow"`},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			d, err := Decide(context.Background(), compile(t, tt.policy), NewPolicyInput(event(TriggerSignUp, "a@example.com"), nil))
			if tt.want == "" {
				if err == nil {
					t.Fatalf("Decide() = %+v, want an error", d)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := outcome(d); got != tt.want {
				t.Errorf("decision = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDecide_V0ResultError(t *testing.T) {
	_, err := Decide(context.Background(), compile(t, `result := {"action": "deny"}`), NewPolicyInput(event(TriggerSignUp, "a@example.com"), nil))
	if err == nil || !strings.Contains(err.Error(), "upgrading-to-v1") {
		t.Errorf("err = %v, want a pointer to the upgrade guide", err)
	}
}

func TestHandle_AllowSetsResponse(t *testing.T) {
	h, err := New(Config{Policy: compile(t, `result := {"actions": ["signup.allow", "user.confirm"]}`)})
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
	h, _ := New(Config{Policy: compile(t, `result := {"actions": [{"action": "signup.deny", "reason": "invite only"}]}`)})
	e := event(TriggerSignUp, "a@example.com")
	err := h.Handle(context.Background(), e)

	var denied *DeniedError
	if !errors.As(err, &denied) || denied.Error() != "invite only" {
		t.Errorf("err = %v, want a DeniedError with the reason", err)
	}
}

// A broken policy must not let sign-ups through.
func TestHandle_FailsClosed(t *testing.T) {
	for name, src := range map[string]string{
		"conflicting rules": "result := {\"actions\": [\"signup.allow\"]}\nresult := {\"actions\": [\"signup.deny\"]} if true",
		"undefined":         `result := {"actions": ["signup.deny"]} if input.never`,
		"typo in action":    `result := {"actions": ["signup.alow"]}`,
		"no decision":       `result := {"actions": ["user.confirm"]}`,
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
const echo = `result := {"actions": [{"action": "signup.deny", "reason": json.marshal(input)}]}`

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
