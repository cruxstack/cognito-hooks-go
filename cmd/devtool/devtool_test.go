package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"
)

const examples = "../../examples/"

// decode reads the JSON objects devtool prints, one after another.
func decode[T any](t *testing.T, out *bytes.Buffer) []T {
	t.Helper()
	var all []T
	dec := json.NewDecoder(out)
	for {
		var v T
		if err := dec.Decode(&v); err == io.EOF {
			return all
		} else if err != nil {
			t.Fatal(err)
		}
		all = append(all, v)
	}
}

func outcomes(t *testing.T, args ...string) ([]string, error) {
	t.Helper()
	var out bytes.Buffer
	err := evalCmd(context.Background(), args, &out)
	var got []string
	for _, r := range decode[evalResult](t, &out) {
		got = append(got, r.Outcome)
	}
	return got, err
}

func TestEval(t *testing.T) {
	tests := map[string]struct {
		args []string
		want []string
	}{
		"presignup": {
			args: []string{"-presignup-policy", examples + "policies/presignup/domains.rego", "-events", examples + "events/presignup.json"},
			want: []string{"signup.allow", "signup.deny: Sign-up is limited to example.com and example.org addresses.", "signup.allow", "signup.allow", "signup.allow"},
		},
		"presignup flags": {
			args: []string{"-presignup-policy", examples + "policies/presignup/auto-confirm.rego", "-events", examples + "events/presignup.json"},
			want: []string{"signup.allow", "signup.allow", "signup.allow", "signup.allow", "signup.allow, user.confirm"},
		},
		"verdict applies to the verified triggers only": {
			args: []string{"-presignup-policy", examples + "policies/presignup/verification.rego", "-verdict", "invalid", "-events", examples + "events/presignup.json"},
			want: []string{"signup.deny: Enter an email address that can receive email.", "signup.deny: Enter an email address that can receive email.", "signup.allow", "signup.allow", "signup.deny: Enter an email address that can receive email."},
		},
		"postconfirmation": {
			args: []string{"-postconfirmation-policy", examples + "policies/postconfirmation/skip-clients.rego", "-events", examples + "events/postconfirmation.json"},
			want: []string{"password.replace", "password.replace", "password.skip: federated user", "password.skip: end-to-end test client"},
		},
		"postconfirmation without a policy": {
			args: []string{"-events", examples + "events/postconfirmation.json"},
			want: []string{"password.replace", "password.replace", "password.skip: federated user", "password.replace"},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := outcomes(t, tt.args...)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("outcomes =\n  %q\nwant\n  %q", got, tt.want)
			}
		})
	}
}

func TestEval_FailsOnPolicyErrors(t *testing.T) {
	// PreSignUp events without a PreSignUp policy
	got, err := outcomes(t, "-events", examples+"events/presignup.json")
	if err == nil || !strings.Contains(err.Error(), "5 of 5 events failed") {
		t.Errorf("err = %v, want every event to fail", err)
	}
	if len(got) != 5 || got[0] != "error" {
		t.Errorf("outcomes = %q", got)
	}

	if _, err := outcomes(t, "-presignup-policy", examples+"policies/presignup/allow.rego", "-verdict", "maybe", "-events", examples+"events/presignup.json"); err == nil {
		t.Error("expected an error for an unknown verdict")
	}
}

func TestRun(t *testing.T) {
	t.Setenv("APP_LOG_LEVEL", "error")
	t.Setenv("APP_PRESIGNUP_ENABLED", "true")
	t.Setenv("APP_PRESIGNUP_POLICY_PATH", examples+"policies/presignup/domains.rego")
	t.Setenv("APP_POSTCONFIRMATION_ENABLED", "true")

	var out bytes.Buffer
	if err := runCmd(context.Background(), []string{"-env", "", "-events", examples + "events/presignup.json"}, &out); err != nil {
		t.Fatal(err)
	}
	results := decode[runResult](t, &out)
	if len(results) != 5 || results[0].Response == nil || results[1].Denied == "" {
		t.Errorf("results = %+v, want the second sign-up denied", results)
	}

	out.Reset()
	if err := runCmd(context.Background(), []string{"-env", "", "-events", examples + "events/postconfirmation.json"}, &out); err != nil {
		t.Fatal(err)
	}
	if results := decode[runResult](t, &out); len(results) != 4 || results[0].Error != "" {
		t.Errorf("results = %+v", results)
	}
}

func TestRun_ConfigurationErrors(t *testing.T) {
	t.Setenv("APP_POLICY_PATH", "policy.rego")
	err := runCmd(context.Background(), []string{"-env", "", "-events", examples + "events/presignup.json"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "APP_POLICY_PATH was removed") {
		t.Errorf("err = %v, want a configuration error", err)
	}
}
