package e2e

import (
	"encoding/json"
	"strings"
	"testing"
)

// One function can serve both triggers.
func TestRouting_BothHooks(t *testing.T) {
	e := newEnv(t, map[string]string{
		"APP_PRESIGNUP_ENABLED":        "true",
		"APP_PRESIGNUP_POLICY_PATH":    policies + "presignup/allow.rego",
		"APP_POSTCONFIRMATION_ENABLED": "true",
	})

	e.mustHandle(preSignUpEvent("PreSignUp_SignUp", "1example23456789", "emma@example.com"))
	e.mustHandle(postConfirmationEvent("PostConfirmation_ConfirmSignUp", "1example23456789", "CONFIRMED"))
	if got := len(e.cognito.replaced()); got != 1 {
		t.Errorf("replaced %d passwords, want 1", got)
	}
}

// An event for a hook that isn't enabled is an error, so a function attached
// to the wrong trigger is noticed instead of letting sign-ups through
// unchecked.
func TestRouting_DisabledOrUnknownTriggerIsAnError(t *testing.T) {
	e := newEnv(t, map[string]string{"APP_POSTCONFIRMATION_ENABLED": "true"})

	tests := map[string]json.RawMessage{
		"disabled hook":   preSignUpEvent("PreSignUp_SignUp", "1example23456789", "emma@example.com"),
		"unknown trigger": event("PreAuthentication_Authentication", "1example23456789", "user-1", map[string]any{}, map[string]any{}),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := e.handle(raw); err == nil || !strings.Contains(err.Error(), "not") {
				t.Errorf("err = %v, want an error", err)
			}
		})
	}
	if got := len(e.cognito.replaced()); got != 0 {
		t.Errorf("replaced %d passwords, want 0", got)
	}
}
