package e2e

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/cruxstack/cognito-hooks-go/internal/config"
	"github.com/cruxstack/cognito-hooks-go/internal/handlers"
)

// mockCognito records AdminSetUserPassword calls without any network
type mockCognito struct {
	calls []*cip.AdminSetUserPasswordInput
	err   error
}

func (m *mockCognito) AdminSetUserPassword(ctx context.Context, params *cip.AdminSetUserPasswordInput, optFns ...func(*cip.Options)) (*cip.AdminSetUserPasswordOutput, error) {
	m.calls = append(m.calls, params)
	return &cip.AdminSetUserPasswordOutput{}, m.err
}

func postConfirmationEvent(trigger, status string) events.CognitoEventUserPoolsPostConfirmation {
	evt := events.CognitoEventUserPoolsPostConfirmation{}
	evt.TriggerSource = trigger
	evt.UserPoolID = "us-east-1_EXAMPLE"
	evt.UserName = "8a1b2c3d-0000-4000-8000-000000000001"
	evt.CallerContext.ClientID = "web"
	evt.Request.UserAttributes = map[string]string{
		"sub":                 "8a1b2c3d-0000-4000-8000-000000000001",
		"email":               "user@example.com",
		"cognito:user_status": status,
	}
	return evt
}

func newPostConfirmationHandler(t *testing.T, policyPath string, m *mockCognito) *handlers.PostConfirmationHandler {
	t.Helper()
	h, err := handlers.NewPostConfirmationHandler(&config.Config{AppLogLevel: "debug", AppPolicyPath: policyPath}, m)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	return h
}

func TestPostConfirmation_ScramblesNativeUsers(t *testing.T) {
	for _, trigger := range []string{"PostConfirmation_ConfirmSignUp", "PostConfirmation_ConfirmForgotPassword"} {
		t.Run(trigger, func(t *testing.T) {
			m := &mockCognito{}
			h := newPostConfirmationHandler(t, "", m)

			if _, err := h.Handle(context.Background(), postConfirmationEvent(trigger, "CONFIRMED")); err != nil {
				t.Fatalf("handle: %v", err)
			}
			if len(m.calls) != 1 {
				t.Fatalf("AdminSetUserPassword calls = %d, want 1", len(m.calls))
			}
			c := m.calls[0]
			if aws.ToString(c.UserPoolId) != "us-east-1_EXAMPLE" || aws.ToString(c.Username) != "8a1b2c3d-0000-4000-8000-000000000001" {
				t.Fatalf("unexpected target: pool=%s user=%s", aws.ToString(c.UserPoolId), aws.ToString(c.Username))
			}
			if !c.Permanent {
				t.Fatal("password must be permanent")
			}
			if len(aws.ToString(c.Password)) != handlers.PasswordLength {
				t.Fatalf("password length = %d, want %d", len(aws.ToString(c.Password)), handlers.PasswordLength)
			}
		})
	}
}

func TestPostConfirmation_SkipsFederatedUsers(t *testing.T) {
	m := &mockCognito{}
	h := newPostConfirmationHandler(t, "", m)

	if _, err := h.Handle(context.Background(), postConfirmationEvent("PostConfirmation_ConfirmSignUp", "EXTERNAL_PROVIDER")); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(m.calls) != 0 {
		t.Fatalf("AdminSetUserPassword calls = %d, want 0", len(m.calls))
	}
}

func TestPostConfirmation_PolicyCanSkip(t *testing.T) {
	policy := writeTempPolicy(t, `
package cognito_hook_postconfirmation
import rego.v1

result := { "action": "skip", "reason": "test account" } if {
	input.callerContext.clientId == "web"
} else := { "action": "scramble" }
`)
	m := &mockCognito{}
	h := newPostConfirmationHandler(t, policy, m)

	if _, err := h.Handle(context.Background(), postConfirmationEvent("PostConfirmation_ConfirmSignUp", "CONFIRMED")); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(m.calls) != 0 {
		t.Fatalf("AdminSetUserPassword calls = %d, want 0", len(m.calls))
	}
}

func TestPostConfirmation_PolicyErrorStillScrambles(t *testing.T) {
	policy := writeTempPolicy(t, `
package cognito_hook_postconfirmation
import rego.v1

result := "not an object"
`)
	m := &mockCognito{}
	h := newPostConfirmationHandler(t, policy, m)

	if _, err := h.Handle(context.Background(), postConfirmationEvent("PostConfirmation_ConfirmSignUp", "CONFIRMED")); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(m.calls) != 1 {
		t.Fatalf("AdminSetUserPassword calls = %d, want 1", len(m.calls))
	}
}

func TestPostConfirmation_CognitoErrorDoesNotFailConfirmation(t *testing.T) {
	m := &mockCognito{err: errors.New("throttled")}
	h := newPostConfirmationHandler(t, "", m)

	if _, err := h.Handle(context.Background(), postConfirmationEvent("PostConfirmation_ConfirmSignUp", "CONFIRMED")); err != nil {
		t.Fatalf("handle returned %v, want nil", err)
	}
	if len(m.calls) != 1 {
		t.Fatalf("AdminSetUserPassword calls = %d, want 1", len(m.calls))
	}
}
