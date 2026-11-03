package e2e

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/cruxstack/cognito-hooks-go/internal/app"
	"github.com/cruxstack/cognito-hooks-go/internal/config"
)

func TestPostConfirmation_ReplacesNativeUsersPasswords(t *testing.T) {
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
	if got := e.cognito.replaced(); !slices.Equal(got, want) {
		t.Errorf("replaced = %v, want %v (federated users keep theirs)", got, want)
	}
}

func TestPostConfirmation_PolicySkipsTestClient(t *testing.T) {
	e := newEnv(t, map[string]string{
		"APP_POSTCONFIRMATION_ENABLED":     "true",
		"APP_POSTCONFIRMATION_POLICY_PATH": policies + "postconfirmation/skip-clients.rego",
	})

	e.mustHandle(postConfirmationEvent("PostConfirmation_ConfirmSignUp", "9test8client7id6example", "CONFIRMED"))
	if got := len(e.cognito.replaced()); got != 0 {
		t.Errorf("replaced %d passwords, want 0 for the test client", got)
	}
	e.mustHandle(postConfirmationEvent("PostConfirmation_ConfirmSignUp", "1example23456789", "CONFIRMED"))
	if got := len(e.cognito.replaced()); got != 1 {
		t.Errorf("replaced %d passwords, want 1", got)
	}
}

// A policy that fails at evaluation time still replaces the password.
func TestPostConfirmation_BrokenPolicyStillReplaces(t *testing.T) {
	e := newEnv(t, map[string]string{
		"APP_POSTCONFIRMATION_ENABLED":     "true",
		"APP_POSTCONFIRMATION_POLICY_PATH": writePolicy(t, "package cognito_hook_postconfirmation\n\nresult := \"skip\"\n"),
	})
	e.mustHandle(postConfirmationEvent("PostConfirmation_ConfirmSignUp", "1example23456789", "CONFIRMED"))
	if got := len(e.cognito.replaced()); got != 1 {
		t.Errorf("replaced %d passwords, want 1", got)
	}
}

// A policy that skips nobody because of a misspelled package would be easy to
// miss, so it stops the function from starting.
func TestPostConfirmation_MisspelledPolicyFailsAtStartup(t *testing.T) {
	cfg, err := config.Load(func(k string) (string, bool) {
		v, ok := map[string]string{
			"APP_POSTCONFIRMATION_ENABLED":     "true",
			"APP_POSTCONFIRMATION_POLICY_PATH": writePolicy(t, "package cognito_hook_post_confirmation\n\nresult := {\"actions\": [\"password.skip\"]}\n"),
		}[k]
		return v, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.New(context.Background(), cfg, aws.Config{}, app.WithCognitoClient(&fakeCognito{})); err == nil ||
		!strings.Contains(err.Error(), "does not define data.cognito_hook_postconfirmation.result") {
		t.Errorf("app.New() = %v, want an error naming the missing rule", err)
	}
}

// The user is already confirmed, so a Cognito failure is logged and the
// confirmation still succeeds.
func TestPostConfirmation_CognitoErrorDoesNotFail(t *testing.T) {
	e := newEnv(t, map[string]string{"APP_POSTCONFIRMATION_ENABLED": "true"})
	e.cognito.err = errors.New("TooManyRequestsException")

	e.mustHandle(postConfirmationEvent("PostConfirmation_ConfirmSignUp", "1example23456789", "CONFIRMED"))
	if got := len(e.cognito.replaced()); got != 1 {
		t.Errorf("AdminSetUserPassword calls = %d, want 1", got)
	}
}
