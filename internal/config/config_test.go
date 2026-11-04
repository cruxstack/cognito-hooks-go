package config

import (
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
)

func load(vars map[string]string) (*Config, error) {
	return Load(func(k string) (string, bool) {
		v, ok := vars[k]
		return v, ok
	})
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := load(map[string]string{
		"APP_PRESIGNUP_ENABLED":     "true",
		"APP_PRESIGNUP_POLICY_PATH": "policy.rego",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := &Config{
		LogLevel:  slog.LevelInfo,
		PreSignUp: PreSignUp{Enabled: true, PolicyPath: "policy.rego"},
		EmailVerification: EmailVerification{
			Triggers: []string{"PreSignUp_SignUp"},
		},
		SendGrid: SendGrid{APIHost: "https://api.sendgrid.com"},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("config =\n  %+v\nwant\n  %+v", cfg, want)
	}
}

func TestLoad_Everything(t *testing.T) {
	cfg, err := load(map[string]string{
		"APP_LOG_LEVEL":                              "DEBUG",
		"APP_PRESIGNUP_ENABLED":                      "true",
		"APP_PRESIGNUP_POLICY_PATH":                  " presignup.rego ",
		"APP_POSTCONFIRMATION_ENABLED":               "1",
		"APP_POSTCONFIRMATION_POLICY_PATH":           "postconfirmation.rego",
		"APP_POSTCONFIRMATION_ROTATION_TABLE":        "rotations",
		"APP_PREAUTHENTICATION_ENABLED":              "true",
		"APP_PREAUTHENTICATION_POLICY_PATH":          "preauthentication.rego",
		"APP_PREAUTHENTICATION_ROTATE_BEFORE":        "2026-11-01T00:00:00-05:00",
		"APP_PREAUTHENTICATION_ROTATION_TABLE":       "rotations",
		"APP_EMAIL_VERIFICATION_ENABLED":             "true",
		"APP_EMAIL_VERIFICATION_FOR_TRIGGER_SOURCES": "PreSignUp_SignUp, PreSignUp_AdminCreateUser,",
		"APP_EMAIL_VERIFICATION_ALLOWLIST":           "Example.com, internal.test",
		"APP_SENDGRID_API_HOST":                      "https://api.eu.sendgrid.com",
		"APP_SENDGRID_EMAIL_VERIFICATION_API_KEY":    "SG.key",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := &Config{
		LogLevel:         slog.LevelDebug,
		PreSignUp:        PreSignUp{Enabled: true, PolicyPath: "presignup.rego"},
		PostConfirmation: PostConfirmation{Enabled: true, PolicyPath: "postconfirmation.rego", RotationTable: "rotations"},
		PreAuthentication: PreAuthentication{
			Enabled:       true,
			PolicyPath:    "preauthentication.rego",
			RotateBefore:  time.Date(2026, 11, 1, 5, 0, 0, 0, time.UTC),
			RotationTable: "rotations",
		},
		EmailVerification: EmailVerification{
			Enabled:   true,
			Triggers:  []string{"PreSignUp_SignUp", "PreSignUp_AdminCreateUser"},
			Allowlist: []string{"example.com", "internal.test"},
		},
		SendGrid: SendGrid{APIHost: "https://api.eu.sendgrid.com", VerificationAPIKey: "SG.key"},
	}
	if !cfg.PreAuthentication.RotateBefore.Equal(want.PreAuthentication.RotateBefore) {
		t.Errorf("rotate before = %v, want %v", cfg.PreAuthentication.RotateBefore, want.PreAuthentication.RotateBefore)
	}
	cfg.PreAuthentication.RotateBefore = want.PreAuthentication.RotateBefore
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("config =\n  %+v\nwant\n  %+v", cfg, want)
	}
}

func TestLoad_PostConfirmationPolicyIsOptional(t *testing.T) {
	cfg, err := load(map[string]string{"APP_POSTCONFIRMATION_ENABLED": "true"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PostConfirmation.Enabled || cfg.PostConfirmation.PolicyPath != "" {
		t.Errorf("post confirmation = %+v", cfg.PostConfirmation)
	}
}

// Verification only applies to PreSignUp, so its settings don't matter to a
// function that only runs PostConfirmation.
func TestLoad_VerificationIsIgnoredWithoutPreSignUp(t *testing.T) {
	_, err := load(map[string]string{
		"APP_POSTCONFIRMATION_ENABLED":               "true",
		"APP_EMAIL_VERIFICATION_ENABLED":             "true",
		"APP_EMAIL_VERIFICATION_FOR_TRIGGER_SOURCES": "SignUp",
	})
	if err != nil {
		t.Errorf("Load() = %v", err)
	}
}

func TestLoad_Errors(t *testing.T) {
	tests := map[string]struct {
		vars map[string]string
		want []string
	}{
		"nothing enabled": {
			vars: map[string]string{},
			want: []string{"at least one of APP_PRESIGNUP_ENABLED, APP_POSTCONFIRMATION_ENABLED, or APP_PREAUTHENTICATION_ENABLED must be true"},
		},
		"preauthentication without a cutoff or table": {
			vars: map[string]string{"APP_PREAUTHENTICATION_ENABLED": "true"},
			want: []string{
				"APP_PREAUTHENTICATION_ROTATION_TABLE is required",
				"APP_PREAUTHENTICATION_ROTATE_BEFORE is required",
			},
		},
		"preauthentication with an invalid cutoff": {
			vars: map[string]string{
				"APP_PREAUTHENTICATION_ENABLED":        "true",
				"APP_PREAUTHENTICATION_ROTATE_BEFORE":  "2026-11-01",
				"APP_PREAUTHENTICATION_ROTATION_TABLE": "rotations",
			},
			want: []string{`APP_PREAUTHENTICATION_ROTATE_BEFORE: "2026-11-01" is not an RFC 3339 timestamp`},
		},
		"preauthentication with a cutoff in the future": {
			vars: map[string]string{
				"APP_PREAUTHENTICATION_ENABLED":        "true",
				"APP_PREAUTHENTICATION_ROTATE_BEFORE":  "2999-01-01T00:00:00Z",
				"APP_PREAUTHENTICATION_ROTATION_TABLE": "rotations",
			},
			want: []string{"APP_PREAUTHENTICATION_ROTATE_BEFORE: 2999-01-01T00:00:00Z is in the future"},
		},
		"presignup without a policy": {
			vars: map[string]string{"APP_PRESIGNUP_ENABLED": "true"},
			want: []string{"APP_PRESIGNUP_POLICY_PATH is required"},
		},
		"invalid values": {
			vars: map[string]string{
				"APP_LOG_LEVEL":                "verbose",
				"APP_PRESIGNUP_ENABLED":        "yes",
				"APP_POSTCONFIRMATION_ENABLED": "true",
				"APP_SENDGRID_API_HOST":        "api.sendgrid.com",
			},
			want: []string{
				`APP_LOG_LEVEL: "verbose" must be one of`,
				`APP_PRESIGNUP_ENABLED: "yes" is not a boolean`,
				`APP_SENDGRID_API_HOST: "api.sendgrid.com" must be an https URL`,
			},
		},
		"verification without a key or with unknown triggers": {
			vars: map[string]string{
				"APP_PRESIGNUP_ENABLED":                      "true",
				"APP_PRESIGNUP_POLICY_PATH":                  "policy.rego",
				"APP_EMAIL_VERIFICATION_ENABLED":             "true",
				"APP_EMAIL_VERIFICATION_FOR_TRIGGER_SOURCES": "SignUp,PreSignUp_SignUp",
			},
			want: []string{
				"APP_SENDGRID_EMAIL_VERIFICATION_API_KEY is required",
				`APP_EMAIL_VERIFICATION_FOR_TRIGGER_SOURCES: unknown trigger source "SignUp"`,
			},
		},
		"removed variables": {
			vars: map[string]string{
				"APP_POSTCONFIRMATION_ENABLED":     "true",
				"APP_POLICY_PATH":                  "./policy.rego",
				"APP_DEBUG_ENABLED":                "false",
				"APP_DEBUG_DATA_PATH":              "fixtures/debug-data.json",
				"APP_EMAIL_VERIFICATION_WHITELIST": "example.com",
			},
			want: []string{
				"APP_POLICY_PATH was removed in v1: use APP_PRESIGNUP_POLICY_PATH",
				"APP_DEBUG_ENABLED was removed in v1: use APP_LOG_LEVEL=debug",
				"APP_DEBUG_DATA_PATH was removed in v1",
				"APP_EMAIL_VERIFICATION_WHITELIST was removed in v1: use APP_EMAIL_VERIFICATION_ALLOWLIST",
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, err := load(tt.vars)
			if err == nil {
				t.Fatalf("Load() = %+v, want an error", cfg)
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error does not mention %q:\n%v", w, err)
				}
			}
		})
	}
}

func TestSecureURL(t *testing.T) {
	for in, want := range map[string]bool{
		"https://api.sendgrid.com":    true,
		"https://api.eu.sendgrid.com": true,
		"http://127.0.0.1:8080":       true,
		"http://localhost:8080":       true,
		"http://[::1]:8080":           true,
		"http://api.sendgrid.com":     false,
		"http://10.0.0.1":             false,
		"api.sendgrid.com":            false,
		"https://":                    false,
		"ftp://api.sendgrid.com":      false,
	} {
		if got := secureURL(in); got != want {
			t.Errorf("secureURL(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLoad_PreAuthenticationPolicyIsOptional(t *testing.T) {
	cfg, err := load(map[string]string{
		"APP_PREAUTHENTICATION_ENABLED":        "true",
		"APP_PREAUTHENTICATION_ROTATE_BEFORE":  "2026-11-01T00:00:00Z",
		"APP_PREAUTHENTICATION_ROTATION_TABLE": "rotations",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p := cfg.PreAuthentication; !p.Enabled || p.PolicyPath != "" || p.RotationTable != "rotations" {
		t.Errorf("pre authentication = %+v", p)
	}
}

// The cutoff only has to have passed when the function starts.
func TestLoad_CutoffIsComparedWithTheCurrentTime(t *testing.T) {
	vars := map[string]string{
		"APP_PREAUTHENTICATION_ENABLED":        "true",
		"APP_PREAUTHENTICATION_ROTATE_BEFORE":  "2030-01-01T00:00:00Z",
		"APP_PREAUTHENTICATION_ROTATION_TABLE": "rotations",
	}
	t.Cleanup(func() { now = time.Now })

	now = func() time.Time { return time.Date(2029, 12, 31, 0, 0, 0, 0, time.UTC) }
	if _, err := load(vars); err == nil {
		t.Error("expected an error for a cutoff in the future")
	}
	now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := load(vars); err != nil {
		t.Errorf("Load() = %v, want the cutoff accepted once it has passed", err)
	}
}

// An empty removed variable, as Terraform writes for an unset value, is not
// an error.
func TestLoad_EmptyRemovedVariableIsIgnored(t *testing.T) {
	if _, err := load(map[string]string{"APP_POSTCONFIRMATION_ENABLED": "true", "APP_POLICY_PATH": ""}); err != nil {
		t.Errorf("Load() = %v", err)
	}
}
