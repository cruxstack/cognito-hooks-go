package e2e

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/cruxstack/cognito-hooks-go/internal/config"
	"github.com/cruxstack/cognito-hooks-go/internal/handlers"
	"github.com/cruxstack/cognito-hooks-go/internal/verifier"
)

type CognitoEventUserPoolsPreSignup struct {
	events.CognitoEventUserPoolsPreSignup
	TriggerSource string
}

// mockVerifier implements verifier.EmailVerifier without any network
type mockVerifier struct {
	validCalls int
	lastEmail  string
	isValid    bool
}

func (m *mockVerifier) VerifyEmail(ctx context.Context, email string) (*verifier.EmailVerificationResult, error) {
	m.validCalls++
	m.lastEmail = email
	return &verifier.EmailVerificationResult{
		Score:        100.0,
		IsValid:      m.isValid,
		IsDisposable: false,
		IsRoleBased:  false,
		Raw:          "{}",
	}, nil
}

func writeTempPolicy(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return p
}

// policy: allow when verification is absent or valid; deny when invalid
const testPolicy = `
package cognito_hook_presignup
import rego.v1

result := { "action": "allow", "response": { "autoConfirmUser": true } } if {
	input.emailVerification == null
} else := { "action": "allow", "response": { "autoConfirmUser": true } } if {
	input.emailVerification.valid
}

result := { "action": "deny", "reason": "invalid" } if {
	input.emailVerification != null
	not input.emailVerification.valid
}
`

func newHandlerWithPolicy(t *testing.T, policyPath string) *handlers.PreSignupHandler {
	t.Helper()
	cfg := &config.Config{
		AppLogLevel:                        "debug",
		AppPolicyPath:                      policyPath,
		EmailVerificationEnabled:           true,
		SendGridApiHost:                    "https://api.sendgrid.com",
		EmailVerificationForTriggerSources: &[]string{"PreSignUp_SignUp"},
	}
	h, err := handlers.NewPreSignupHandler(cfg)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	return h
}

func TestAllow_WhenVerifierValid(t *testing.T) {
	p := writeTempPolicy(t, testPolicy)
	h := newHandlerWithPolicy(t, p)

	// inject mock that always returns valid
	mv := &mockVerifier{isValid: true}
	h.EmailVerifier = mv

	evt := events.CognitoEventUserPoolsPreSignup{}
	evt.TriggerSource = "PreSignUp_SignUp"
	evt.Request = events.CognitoEventUserPoolsPreSignupRequest{
		UserAttributes: map[string]string{"email": "ok@example.com"},
	}

	out, err := h.Handle(context.Background(), evt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !out.Response.AutoConfirmUser {
		t.Fatalf("expected autoConfirmUser=true when allowed")
	}
	if mv.validCalls != 1 {
		t.Fatalf("expected verifier to be called once, got %d", mv.validCalls)
	}
}

func TestDeny_WhenVerifierInvalid(t *testing.T) {
	p := writeTempPolicy(t, testPolicy)
	h := newHandlerWithPolicy(t, p)

	// inject mock that returns invalid
	mv := &mockVerifier{isValid: false}
	h.EmailVerifier = mv

	evt := events.CognitoEventUserPoolsPreSignup{}
	evt.TriggerSource = "PreSignUp_SignUp"
	evt.Request = events.CognitoEventUserPoolsPreSignupRequest{
		UserAttributes: map[string]string{"email": "nope@example.com"},
	}

	_, err := h.Handle(context.Background(), evt)
	if err == nil {
		t.Fatalf("expected error when invalid")
	}
	if mv.validCalls != 1 {
		t.Fatalf("expected verifier to be called once, got %d", mv.validCalls)
	}
}

func TestSkipVerification_ForNonMatchingTrigger(t *testing.T) {
	p := writeTempPolicy(t, testPolicy)
	h := newHandlerWithPolicy(t, p)

	mv := &mockVerifier{isValid: true}
	h.EmailVerifier = mv

	evt := events.CognitoEventUserPoolsPreSignup{}
	evt.TriggerSource = "PreSignUp_ExternalProvider"
	evt.Request = events.CognitoEventUserPoolsPreSignupRequest{
		UserAttributes: map[string]string{"email": "skip@federated.test"},
	}

	out, err := h.Handle(context.Background(), evt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.Response.AutoConfirmUser {
		t.Fatalf("expected allow on external provider")
	}
	if mv.validCalls != 0 {
		t.Fatalf("expected verifier not to be called, got %d", mv.validCalls)
	}
}

func TestWhitelist_BypassesNetwork(t *testing.T) {
	p := writeTempPolicy(t, testPolicy)

	// whitelist example.com and enable verification
	cfg := &config.Config{
		AppLogLevel:                        "debug",
		AppPolicyPath:                      p,
		EmailVerificationEnabled:           true,
		SendGridApiHost:                    "https://api.sendgrid.com",
		EmailVerificationForTriggerSources: &[]string{"PreSignUp_SignUp"},
		EmailVerificationWhitelist:         &[]string{"example.com"},
	}

	h, err := handlers.NewPreSignupHandler(cfg)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	evt := events.CognitoEventUserPoolsPreSignup{}
	evt.TriggerSource = "PreSignUp_SignUp"
	evt.Request = events.CognitoEventUserPoolsPreSignupRequest{
		UserAttributes: map[string]string{"email": "user@example.com"},
	}

	out, err := h.Handle(context.Background(), evt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.Response.AutoConfirmUser {
		t.Fatalf("expected allow for whitelisted domain")
	}
}
