package e2e

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/cruxstack/cognito-hooks-go/internal/app"
	"github.com/cruxstack/cognito-hooks-go/internal/config"
)

func preSignUpEnv(t *testing.T, policy string, vars map[string]string) *env {
	t.Helper()
	all := map[string]string{
		"APP_PRESIGNUP_ENABLED":     "true",
		"APP_PRESIGNUP_POLICY_PATH": policy,
	}
	for k, v := range vars {
		all[k] = v
	}
	return newEnv(t, all)
}

func TestPreSignUp_AllowSetsResponseFlags(t *testing.T) {
	e := preSignUpEnv(t, policies+"presignup/auto-confirm.rego", nil)

	resp := e.mustHandle(preSignUpEvent("PreSignUp_SignUp", "9test8client7id6example", "e2e+1@example.com"))
	r, _ := resp["response"].(map[string]any)
	if r["autoConfirmUser"] != true || r["autoVerifyEmail"] != false || r["autoVerifyPhone"] != false {
		t.Errorf("response = %v, want only autoConfirmUser", r)
	}
	if resp["triggerSource"] != "PreSignUp_SignUp" || resp["userName"] != "8a1b2c3d-0000-4000-8000-000000000001" {
		t.Errorf("response event = %v, want the request event with the response set", resp)
	}

	resp = e.mustHandle(preSignUpEvent("PreSignUp_SignUp", "1example23456789", "emma@example.com"))
	if r, _ := resp["response"].(map[string]any); r["autoConfirmUser"] != false {
		t.Errorf("response = %v, want no flags for other clients", r)
	}
}

// Cognito shows the error message to the user: "PreSignUp failed with error
// <message>."
func TestPreSignUp_DenyReasonReachesTheUser(t *testing.T) {
	e := preSignUpEnv(t, policies+"presignup/domains.rego", nil)

	_, err := e.handle(preSignUpEvent("PreSignUp_SignUp", "1example23456789", "mallory@mailinator.test"))
	if err == nil || err.Error() != "Sign-up is limited to example.com and example.org addresses." {
		t.Errorf("err = %v, want the policy's reason", err)
	}
	e.mustHandle(preSignUpEvent("PreSignUp_SignUp", "1example23456789", "emma@example.com"))
}

// A policy that fails at evaluation time rejects the sign-up instead of
// letting it through, and doesn't leak policy details to the user.
func TestPreSignUp_BrokenPolicyFailsClosed(t *testing.T) {
	for name, src := range map[string]string{
		"conflicting results": "package cognito_hook_presignup\n\nresult := {\"action\": \"allow\"}\n\nresult := {\"action\": \"deny\"} if input.userAttributes.email\n",
		"undefined result":    "package cognito_hook_presignup\n\nresult := {\"action\": \"allow\"} if input.never\n",
		"unknown action":      "package cognito_hook_presignup\n\nresult := {\"action\": \"accept\"}\n",
	} {
		t.Run(name, func(t *testing.T) {
			e := preSignUpEnv(t, writePolicy(t, src), nil)
			_, err := e.handle(preSignUpEvent("PreSignUp_SignUp", "1example23456789", "emma@example.com"))
			if err == nil || err.Error() != "the sign-up policy failed" {
				t.Errorf("err = %v, want the generic policy failure", err)
			}
		})
	}
}

func TestPreSignUp_EmailVerification(t *testing.T) {
	vars := map[string]string{
		"APP_EMAIL_VERIFICATION_ENABLED":          "true",
		"APP_EMAIL_VERIFICATION_ALLOWLIST":        "Example.com",
		"APP_SENDGRID_EMAIL_VERIFICATION_API_KEY": "SG.verify",
	}
	e := preSignUpEnv(t, policies+"presignup/verification.rego", vars)
	e.sendgrid.respond("bounce@invalid.test", map[string]any{"verdict": "Invalid", "score": 0.01})
	e.sendgrid.respond("temp@mailinator.test", map[string]any{
		"verdict": "Risky", "score": 0.4,
		"checks": map[string]any{"domain": map[string]any{"is_suspected_disposable_address": true}},
	})

	if _, err := e.handle(preSignUpEvent("PreSignUp_SignUp", "web", "bounce@invalid.test")); err == nil ||
		!strings.Contains(err.Error(), "can receive email") {
		t.Errorf("undeliverable: err = %v, want a denial", err)
	}
	if _, err := e.handle(preSignUpEvent("PreSignUp_SignUp", "web", "temp@mailinator.test")); err == nil ||
		!strings.Contains(err.Error(), "Disposable") {
		t.Errorf("disposable: err = %v, want a denial", err)
	}
	e.mustHandle(preSignUpEvent("PreSignUp_SignUp", "web", "liam@valid.test"))
	if got := e.sendgrid.validationCount(); got != 3 {
		t.Errorf("validations = %d, want 3", got)
	}

	// the allowlist and triggers that aren't listed skip SendGrid
	e.mustHandle(preSignUpEvent("PreSignUp_SignUp", "web", "emma@example.com"))
	e.mustHandle(preSignUpEvent("PreSignUp_AdminCreateUser", "CLIENT_ID_NOT_APPLICABLE", "bounce@invalid.test"))
	if got := e.sendgrid.validationCount(); got != 3 {
		t.Errorf("validations = %d, want still 3", got)
	}
}

// A SendGrid outage must not block sign-ups: the policy runs without
// input.emailVerification.
func TestPreSignUp_VerificationUnavailable(t *testing.T) {
	e := preSignUpEnv(t, policies+"presignup/verification.rego", map[string]string{
		"APP_EMAIL_VERIFICATION_ENABLED":          "true",
		"APP_SENDGRID_EMAIL_VERIFICATION_API_KEY": "SG.verify",
	})
	e.sendgrid.fail(http.StatusUnauthorized)

	e.mustHandle(preSignUpEvent("PreSignUp_SignUp", "web", "bounce@invalid.test"))
	if got := e.sendgrid.validationCount(); got != 1 {
		t.Errorf("validations = %d, want 1", got)
	}
}

func TestPreSignUp_InvalidPolicyFailsAtStartup(t *testing.T) {
	tests := map[string]string{
		"syntax error":       "package cognito_hook_presignup\n\nresult := {\n",
		"rego v0":            "package cognito_hook_presignup\n\nresult = {\"action\": \"allow\"} { true }\n",
		"misspelled package": "package cognito_hooks_presignup\n\nresult := {\"action\": \"allow\"}\n",
		"misspelled rule":    "package cognito_hook_presignup\n\nresults := {\"action\": \"allow\"}\n",
	}
	for name, src := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, err := config.Load(func(k string) (string, bool) {
				v, ok := map[string]string{"APP_PRESIGNUP_ENABLED": "true", "APP_PRESIGNUP_POLICY_PATH": writePolicy(t, src)}[k]
				return v, ok
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := app.New(context.Background(), cfg, aws.Config{}); err == nil {
				t.Error("app.New() succeeded, want a policy compile error")
			}
		})
	}
}

func writePolicy(t *testing.T, src string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.rego")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
