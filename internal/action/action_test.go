package action

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestResult(t *testing.T) {
	var r Result
	err := json.Unmarshal([]byte(`{"actions": [" Signup.Allow ", {"action": "signup.deny", "reason": "no"}]}`), &r)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Actions) != 2 || r.Actions[0].Name != "signup.allow" || r.Actions[1].Name != "signup.deny" {
		t.Fatalf("actions = %+v", r.Actions)
	}
	if err := r.Check(); err != nil {
		t.Errorf("Check() = %v", err)
	}

	var p struct{ Reason string }
	if err := r.Actions[1].Decode(&p); err != nil || p.Reason != "no" {
		t.Errorf("Decode() = %+v, %v", p, err)
	}
	if err := r.Actions[0].Decode(&struct{}{}); err != nil {
		t.Errorf("a name has no parameters: %v", err)
	}

	b, _ := json.Marshal(r.Actions)
	if want := `["signup.allow",{"action":"signup.deny","reason":"no"}]`; string(b) != want {
		t.Errorf("marshal = %s, want %s", b, want)
	}
}

func TestDecode_UnknownParameterIsAnError(t *testing.T) {
	var a Action
	if err := json.Unmarshal([]byte(`{"action": "signup.deny", "reson": "typo"}`), &a); err != nil {
		t.Fatal(err)
	}
	var p struct{ Reason string }
	if err := a.Decode(&p); err == nil {
		t.Error("expected an error for a misspelled parameter")
	}
	if err := a.Decode(&struct{}{}); err == nil {
		t.Error("expected an error for parameters on an action that takes none")
	}
}

func TestUnmarshal_Errors(t *testing.T) {
	for name, in := range map[string]string{
		"number":           `{"actions": [1]}`,
		"object, no name":  `{"actions": [{"reason": "x"}]}`,
		"object, blank":    `{"actions": [{"action": " "}]}`,
		"name not string":  `{"actions": [{"action": 1}]}`,
		"actions not list": `{"actions": "signup.allow"}`,
	} {
		var r Result
		if err := json.Unmarshal([]byte(in), &r); err == nil {
			t.Errorf("%s: Unmarshal() = %+v, want an error", name, r)
		}
	}
}

func TestCheck_V0Result(t *testing.T) {
	var r Result
	if err := json.Unmarshal([]byte(`{"action": "allow", "response": {}}`), &r); err != nil {
		t.Fatal(err)
	}
	if err := r.Check(); !errors.Is(err, ErrV0Result) {
		t.Errorf("Check() = %v, want ErrV0Result", err)
	}

	var empty Result
	if err := json.Unmarshal([]byte(`{}`), &empty); err != nil || empty.Check() != nil {
		t.Errorf("an empty result is not a v0 result: %v", empty.Check())
	}
}
