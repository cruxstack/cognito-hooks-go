// Package examples_test keeps the example policies working: every policy
// must compile, its Rego unit tests must pass, and the hook must make the
// expected decision for each sample event.
package examples_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/open-policy-agent/opa/v1/tester"

	"github.com/cruxstack/cognito-hooks-go/internal/policy"
	"github.com/cruxstack/cognito-hooks-go/internal/postconfirmation"
	"github.com/cruxstack/cognito-hooks-go/internal/preauthentication"
	"github.com/cruxstack/cognito-hooks-go/internal/presignup"
	"github.com/cruxstack/cognito-hooks-go/internal/verify"
)

func readEvents[E any](t *testing.T, path string) []*E {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var events []*E
	if err := json.Unmarshal(data, &events); err != nil {
		t.Fatal(err)
	}
	return events
}

func load(t *testing.T, path, query string) *policy.Engine {
	t.Helper()
	p, err := policy.Load(context.Background(), path, query)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// staticVerifier returns the same result for every address.
type staticVerifier struct{ result *verify.Result }

func (v staticVerifier) Verify(context.Context, string) (*verify.Result, error) { return v.result, nil }

// preSignUpOutcome runs the hook and returns "allow", "allow:<flags>", or
// "deny".
func preSignUpOutcome(t *testing.T, h *presignup.Hook, e presignup.Event) string {
	t.Helper()
	err := h.Handle(context.Background(), &e)
	var denied *presignup.DeniedError
	switch {
	case errors.As(err, &denied):
		return "deny"
	case err != nil:
		t.Errorf("%s: %v", e.TriggerSource, err)
		return "error"
	}
	var flags []string
	if e.Response.AutoConfirmUser {
		flags = append(flags, "autoConfirmUser")
	}
	if e.Response.AutoVerifyEmail {
		flags = append(flags, "autoVerifyEmail")
	}
	if e.Response.AutoVerifyPhone {
		flags = append(flags, "autoVerifyPhone")
	}
	if len(flags) == 0 {
		return "allow"
	}
	return "allow:" + strings.Join(flags, ",")
}

var preSignUpTests = map[string][]string{
	// events: emma@example.com sign-up, mallory@mailinator.test sign-up,
	// admin-created user, federated user, test client sign-up
	"allow.rego":        {"allow", "allow", "allow", "allow", "allow"},
	"domains.rego":      {"allow", "deny", "allow", "allow", "allow"},
	"auto-confirm.rego": {"allow", "allow", "allow", "allow", "allow:autoConfirmUser"},
	// without verification results, every sign-up is allowed
	"verification.rego": {"allow", "allow", "allow", "allow", "allow"},
}

func TestPreSignUpPolicies(t *testing.T) {
	events := readEvents[presignup.Event](t, "events/presignup.json")
	for name, want := range preSignUpTests {
		t.Run(name, func(t *testing.T) {
			h, err := presignup.New(presignup.Config{Policy: load(t, filepath.Join("policies/presignup", name), presignup.PolicyQuery)})
			if err != nil {
				t.Fatal(err)
			}
			if len(want) != len(events) {
				t.Fatalf("test has %d expectations for %d events", len(want), len(events))
			}
			for i, e := range events {
				if got := preSignUpOutcome(t, h, *e); got != want[i] {
					t.Errorf("event %d (%s) = %s, want %s", i, e.TriggerSource, got, want[i])
				}
			}
		})
	}
}

func TestVerificationPolicy(t *testing.T) {
	events := readEvents[presignup.Event](t, "events/presignup.json")
	pol := load(t, "policies/presignup/verification.rego", presignup.PolicyQuery)

	tests := map[string]struct {
		result *verify.Result
		want   []string
	}{
		// verification runs only for PreSignUp_SignUp (events 0, 1, and 4)
		"undeliverable": {
			result: &verify.Result{Provider: verify.ProviderSendGrid, Valid: false, Verdict: verify.VerdictInvalid},
			want:   []string{"deny", "deny", "allow", "allow", "deny"},
		},
		"disposable": {
			result: &verify.Result{Provider: verify.ProviderSendGrid, Valid: true, Verdict: verify.VerdictRisky, Disposable: true},
			want:   []string{"deny", "deny", "allow", "allow", "deny"},
		},
		"valid": {
			result: &verify.Result{Provider: verify.ProviderSendGrid, Valid: true, Verdict: verify.VerdictValid},
			want:   []string{"allow", "allow", "allow", "allow", "allow"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			h, err := presignup.New(presignup.Config{
				Policy:         pol,
				Verifier:       staticVerifier{tt.result},
				VerifyTriggers: []string{presignup.TriggerSignUp},
			})
			if err != nil {
				t.Fatal(err)
			}
			for i, e := range events {
				if got := preSignUpOutcome(t, h, *e); got != tt.want[i] {
					t.Errorf("event %d (%s) = %s, want %s", i, e.TriggerSource, got, tt.want[i])
				}
			}
		})
	}
}

// countingCognito counts password changes.
type countingCognito struct{ calls int }

func (c *countingCognito) AdminSetUserPassword(context.Context, *cip.AdminSetUserPasswordInput, ...func(*cip.Options)) (*cip.AdminSetUserPasswordOutput, error) {
	c.calls++
	return &cip.AdminSetUserPasswordOutput{}, nil
}

// AdminGetUser fails: every sample event has a status and a sub.
func (c *countingCognito) AdminGetUser(context.Context, *cip.AdminGetUserInput, ...func(*cip.Options)) (*cip.AdminGetUserOutput, error) {
	return nil, errors.New("unexpected AdminGetUser call")
}

// emptyStore has no rotation records.
type emptyStore struct{}

func (emptyStore) LastReplaced(context.Context, string) (*time.Time, error) { return nil, nil }
func (emptyStore) Record(context.Context, string, time.Time) error          { return nil }

var postConfirmationTests = map[string][]bool{
	// events: sign-up confirmation, password reset, federated user, test
	// client; true means the password is replaced
	"":                  {true, true, false, true},
	"skip-clients.rego": {true, true, false, false},
}

func TestPostConfirmationPolicies(t *testing.T) {
	events := readEvents[postconfirmation.Event](t, "events/postconfirmation.json")
	for name, want := range postConfirmationTests {
		t.Run("policy="+name, func(t *testing.T) {
			var pol *policy.Engine
			if name != "" {
				pol = load(t, filepath.Join("policies/postconfirmation", name), postconfirmation.PolicyQuery)
			}
			if len(want) != len(events) {
				t.Fatalf("test has %d expectations for %d events", len(want), len(events))
			}
			for i, e := range events {
				c := &countingCognito{}
				h, err := postconfirmation.New(postconfirmation.Config{Cognito: c, Policy: pol})
				if err != nil {
					t.Fatal(err)
				}
				if err := h.Handle(context.Background(), e); err != nil {
					t.Fatal(err)
				}
				if got := c.calls == 1; got != want[i] {
					t.Errorf("event %d (%s): replaced = %v, want %v", i, e.TriggerSource, got, want[i])
				}
			}
		})
	}
}

var preAuthenticationTests = map[string][]bool{
	// events: native user, federated user, unconfirmed user, unknown user,
	// test user by sub, test user by username; true means the password is
	// replaced (no event's user has a rotation record)
	"":                {true, false, false, false, true, true},
	"skip-users.rego": {true, false, false, false, false, false},
}

func TestPreAuthenticationPolicies(t *testing.T) {
	events := readEvents[preauthentication.Event](t, "events/preauthentication.json")
	for name, want := range preAuthenticationTests {
		t.Run("policy="+name, func(t *testing.T) {
			var pol *policy.Engine
			if name != "" {
				pol = load(t, filepath.Join("policies/preauthentication", name), preauthentication.PolicyQuery)
			}
			if len(want) != len(events) {
				t.Fatalf("test has %d expectations for %d events", len(want), len(events))
			}
			for i, e := range events {
				c := &countingCognito{}
				h, err := preauthentication.New(preauthentication.Config{
					Cognito:      c,
					Rotations:    emptyStore{},
					RotateBefore: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
					Policy:       pol,
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := h.Handle(context.Background(), e); err != nil {
					t.Fatal(err)
				}
				if got := c.calls == 1; got != want[i] {
					t.Errorf("event %d (%s): replaced = %v, want %v", i, e.UserName, got, want[i])
				}
			}
		})
	}
}

func TestEveryPolicyIsTested(t *testing.T) {
	tested := map[string]bool{}
	for name := range preSignUpTests {
		tested["policies/presignup/"+name] = true
	}
	for name := range postConfirmationTests {
		tested["policies/postconfirmation/"+name] = true
	}
	for name := range preAuthenticationTests {
		tested["policies/preauthentication/"+name] = true
	}

	files, err := filepath.Glob("policies/*/*.rego")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !strings.HasSuffix(f, "_test.rego") && !tested[filepath.ToSlash(f)] {
			t.Errorf("%s has no expectations in this file", f)
		}
	}
}

// The Terraform module requires a policy to start with its package line.
func TestPoliciesStartWithTheirPackage(t *testing.T) {
	for dir, pkg := range map[string]string{
		"policies/presignup":         "package cognito_hook_presignup\n",
		"policies/postconfirmation":  "package cognito_hook_postconfirmation\n",
		"policies/preauthentication": "package cognito_hook_preauthentication\n",
	} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.rego"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.rego") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(string(src), pkg) {
				t.Errorf("%s does not start with %q", f, strings.TrimSpace(pkg))
			}
		}
	}
}

// TestRegoUnitTests runs each *_test.rego file with the policy it tests, as
// "opa test policy.rego policy_test.rego" would.
func TestRegoUnitTests(t *testing.T) {
	tests, err := filepath.Glob("policies/*/*_test.rego")
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) == 0 {
		t.Fatal("no rego tests found")
	}
	for _, testFile := range tests {
		policyFile := strings.TrimSuffix(testFile, "_test.rego") + ".rego"
		t.Run(testFile, func(t *testing.T) {
			results, err := tester.Run(context.Background(), policyFile, testFile)
			if err != nil {
				t.Fatal(err)
			}
			if len(results) == 0 {
				t.Fatal("no rego tests ran")
			}
			for _, r := range results {
				if !r.Pass() {
					t.Errorf("%s: %s", r.Name, r.String())
				}
			}
		})
	}
}
