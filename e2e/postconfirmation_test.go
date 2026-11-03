package e2e

import (
	"errors"
	"slices"
	"testing"
)

func TestPostConfirmation_ScramblesNativeUsers(t *testing.T) {
	e := newEnv(t, map[string]string{"APP_POSTCONFIRMATION_ENABLED": "true"})

	for _, trigger := range []string{"PostConfirmation_ConfirmSignUp", "PostConfirmation_ConfirmForgotPassword"} {
		resp := e.mustHandle(postConfirmationEvent(trigger, "1example23456789", "CONFIRMED"))
		if resp["triggerSource"] != trigger {
			t.Errorf("response = %v, want the request event", resp)
		}
	}
	e.mustHandle(postConfirmationEvent("PostConfirmation_ConfirmSignUp", "1example23456789", "EXTERNAL_PROVIDER"))

	want := []string{
		"us-east-1_EXAMPLE/8a1b2c3d-0000-4000-8000-000000000001",
		"us-east-1_EXAMPLE/8a1b2c3d-0000-4000-8000-000000000001",
	}
	if got := e.cognito.scrambled(); !slices.Equal(got, want) {
		t.Errorf("scrambled = %v, want %v (federated users are skipped)", got, want)
	}
}

func TestPostConfirmation_PolicySkipsTestClient(t *testing.T) {
	e := newEnv(t, map[string]string{
		"APP_POSTCONFIRMATION_ENABLED":     "true",
		"APP_POSTCONFIRMATION_POLICY_PATH": policies + "postconfirmation/skip-clients.rego",
	})

	e.mustHandle(postConfirmationEvent("PostConfirmation_ConfirmSignUp", "9test8client7id6example", "CONFIRMED"))
	if got := len(e.cognito.scrambled()); got != 0 {
		t.Errorf("scrambled %d users, want 0 for the test client", got)
	}
	e.mustHandle(postConfirmationEvent("PostConfirmation_ConfirmSignUp", "1example23456789", "CONFIRMED"))
	if got := len(e.cognito.scrambled()); got != 1 {
		t.Errorf("scrambled %d users, want 1", got)
	}
}

// A policy that fails at evaluation time still scrambles the password.
func TestPostConfirmation_BrokenPolicyStillScrambles(t *testing.T) {
	e := newEnv(t, map[string]string{
		"APP_POSTCONFIRMATION_ENABLED":     "true",
		"APP_POSTCONFIRMATION_POLICY_PATH": writePolicy(t, "package cognito_hook_postconfirmation\n\nresult := \"skip\"\n"),
	})
	e.mustHandle(postConfirmationEvent("PostConfirmation_ConfirmSignUp", "1example23456789", "CONFIRMED"))
	if got := len(e.cognito.scrambled()); got != 1 {
		t.Errorf("scrambled %d users, want 1", got)
	}
}

// The user is already confirmed, so a Cognito failure is logged and the
// confirmation still succeeds.
func TestPostConfirmation_CognitoErrorDoesNotFail(t *testing.T) {
	e := newEnv(t, map[string]string{"APP_POSTCONFIRMATION_ENABLED": "true"})
	e.cognito.err = errors.New("TooManyRequestsException")

	e.mustHandle(postConfirmationEvent("PostConfirmation_ConfirmSignUp", "1example23456789", "CONFIRMED"))
	if got := len(e.cognito.scrambled()); got != 1 {
		t.Errorf("AdminSetUserPassword calls = %d, want 1", got)
	}
}
