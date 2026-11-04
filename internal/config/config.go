// Package config reads the configuration from environment variables. Invalid
// or contradictory settings are errors, so a misconfigured function fails at
// startup instead of misbehaving on a user's sign-up.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cruxstack/cognito-hooks-go/internal/presignup"
	"github.com/cruxstack/cognito-hooks-go/internal/sendgrid"
)

// Config is the function's configuration.
type Config struct {
	LogLevel slog.Level

	PreSignUp         PreSignUp
	PostConfirmation  PostConfirmation
	PreAuthentication PreAuthentication
	EmailVerification EmailVerification
	SendGrid          SendGrid
}

// PreSignUp configures the PreSignUp hook.
type PreSignUp struct {
	Enabled    bool
	PolicyPath string
}

// PostConfirmation configures the PostConfirmation hook.
type PostConfirmation struct {
	Enabled bool
	// PolicyPath is optional; without a policy every native user's password
	// is replaced.
	PolicyPath string
	// RotationTable is optional. When set, each replacement is recorded in
	// the PreAuthentication hook's DynamoDB table.
	RotationTable string
}

// PreAuthentication configures the PreAuthentication hook.
type PreAuthentication struct {
	Enabled bool
	// PolicyPath is optional; without a policy every native, confirmed
	// user's stale password is replaced.
	PolicyPath string
	// RotateBefore is the cutoff: a password the hooks haven't replaced
	// since this time is replaced at the user's next sign-in.
	RotateBefore time.Time
	// RotationTable is the DynamoDB table that records each replacement.
	RotationTable string
}

// EmailVerification configures email verification for the PreSignUp hook.
type EmailVerification struct {
	Enabled bool
	// Triggers are the PreSignUp trigger sources to verify addresses for.
	Triggers []string
	// Allowlist holds domains that are treated as valid without calling
	// SendGrid.
	Allowlist []string
}

// SendGrid holds the SendGrid API settings.
type SendGrid struct {
	APIHost            string
	VerificationAPIKey string
}

// removed lists variables from v0 that are no longer read, with what to use
// instead. Setting one is an error so an old configuration can't silently
// change behavior.
var removed = map[string]string{
	"APP_POLICY_PATH":                  "APP_PRESIGNUP_POLICY_PATH or APP_POSTCONFIRMATION_POLICY_PATH, with APP_PRESIGNUP_ENABLED or APP_POSTCONFIRMATION_ENABLED",
	"APP_DEBUG_ENABLED":                "APP_LOG_LEVEL=debug, and the devtool CLI for local runs",
	"APP_DEBUG_DATA_PATH":              "the devtool -events flag",
	"APP_EMAIL_VERIFICATION_WHITELIST": "APP_EMAIL_VERIFICATION_ALLOWLIST",
}

// now returns the current time; tests replace it.
var now = time.Now

// FromEnv reads the configuration from the process environment.
func FromEnv() (*Config, error) {
	return Load(os.LookupEnv)
}

// Load reads the configuration with lookup, which has the signature of
// os.LookupEnv. All problems are reported together.
func Load(lookup func(string) (string, bool)) (*Config, error) {
	r := reader{lookup: lookup}

	for _, key := range slices.Sorted(maps.Keys(removed)) {
		if r.str(key) != "" {
			r.fail(fmt.Errorf("%s was removed in v1: use %s", key, removed[key]))
		}
	}

	cfg := &Config{
		LogLevel: r.level("APP_LOG_LEVEL", slog.LevelInfo),
		PreSignUp: PreSignUp{
			Enabled:    r.boolean("APP_PRESIGNUP_ENABLED"),
			PolicyPath: r.str("APP_PRESIGNUP_POLICY_PATH"),
		},
		PostConfirmation: PostConfirmation{
			Enabled:       r.boolean("APP_POSTCONFIRMATION_ENABLED"),
			PolicyPath:    r.str("APP_POSTCONFIRMATION_POLICY_PATH"),
			RotationTable: r.str("APP_POSTCONFIRMATION_ROTATION_TABLE"),
		},
		PreAuthentication: PreAuthentication{
			Enabled:       r.boolean("APP_PREAUTHENTICATION_ENABLED"),
			PolicyPath:    r.str("APP_PREAUTHENTICATION_POLICY_PATH"),
			RotateBefore:  r.timestamp("APP_PREAUTHENTICATION_ROTATE_BEFORE"),
			RotationTable: r.str("APP_PREAUTHENTICATION_ROTATION_TABLE"),
		},
		EmailVerification: EmailVerification{
			Enabled:   r.boolean("APP_EMAIL_VERIFICATION_ENABLED"),
			Triggers:  r.list("APP_EMAIL_VERIFICATION_FOR_TRIGGER_SOURCES", []string{presignup.TriggerSignUp}),
			Allowlist: lower(r.list("APP_EMAIL_VERIFICATION_ALLOWLIST", nil)),
		},
		SendGrid: SendGrid{
			APIHost:            r.strOr("APP_SENDGRID_API_HOST", sendgrid.DefaultBaseURL),
			VerificationAPIKey: r.str("APP_SENDGRID_EMAIL_VERIFICATION_API_KEY"),
		},
	}

	r.errs = append(r.errs, cfg.validate()...)
	if len(r.errs) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  %w", joinIndented(r.errs))
	}
	return cfg, nil
}

func (c *Config) validate() []error {
	var errs []error
	req := func(ok bool, msg string) {
		if !ok {
			errs = append(errs, errors.New(msg))
		}
	}

	req(c.PreSignUp.Enabled || c.PostConfirmation.Enabled || c.PreAuthentication.Enabled,
		"at least one of APP_PRESIGNUP_ENABLED, APP_POSTCONFIRMATION_ENABLED, or APP_PREAUTHENTICATION_ENABLED must be true")

	if c.PreSignUp.Enabled {
		req(c.PreSignUp.PolicyPath != "", "APP_PRESIGNUP_POLICY_PATH is required when APP_PRESIGNUP_ENABLED is true")

		// verification only applies to PreSignUp, so its settings are only
		// checked when that hook is enabled
		if v := c.EmailVerification; v.Enabled {
			req(c.SendGrid.VerificationAPIKey != "",
				"APP_SENDGRID_EMAIL_VERIFICATION_API_KEY is required when APP_EMAIL_VERIFICATION_ENABLED is true")
			for _, t := range v.Triggers {
				if !slices.Contains(presignup.Triggers, t) {
					errs = append(errs, fmt.Errorf("APP_EMAIL_VERIFICATION_FOR_TRIGGER_SOURCES: unknown trigger source %q: must be one of %v", t, presignup.Triggers))
				}
			}
		}
	}

	if p := c.PreAuthentication; p.Enabled {
		req(p.RotationTable != "", "APP_PREAUTHENTICATION_ROTATION_TABLE is required when APP_PREAUTHENTICATION_ENABLED is true")
		switch {
		case p.RotateBefore.IsZero():
			req(false, "APP_PREAUTHENTICATION_ROTATE_BEFORE is required when APP_PREAUTHENTICATION_ENABLED is true")
		case p.RotateBefore.After(now()):
			// every replacement would be before the cutoff, so every sign-in
			// would replace the password again until the cutoff passes
			errs = append(errs, fmt.Errorf("APP_PREAUTHENTICATION_ROTATE_BEFORE: %s is in the future: use a time that has passed, such as when the passwords were exposed",
				p.RotateBefore.Format(time.RFC3339)))
		}
	}

	if !secureURL(c.SendGrid.APIHost) {
		errs = append(errs, fmt.Errorf("APP_SENDGRID_API_HOST: %q must be an https URL such as %s", c.SendGrid.APIHost, sendgrid.DefaultBaseURL))
	}

	return errs
}

// secureURL reports whether s is an https URL, or an http URL for a loopback
// host such as a local test server. The API key is sent with every request,
// so it must not cross a network in plaintext.
func secureURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		return host == "localhost" || (ip != nil && ip.IsLoopback())
	}
	return false
}

// reader parses environment variables and collects errors.
type reader struct {
	lookup func(string) (string, bool)
	errs   []error
}

func (r *reader) fail(err error) {
	r.errs = append(r.errs, err)
}

// str returns the trimmed value of key, or "" when unset.
func (r *reader) str(key string) string {
	v, _ := r.lookup(key)
	return strings.TrimSpace(v)
}

// strOr returns the value of key, or def when unset or empty.
func (r *reader) strOr(key, def string) string {
	if v := r.str(key); v != "" {
		return v
	}
	return def
}

// boolean parses a boolean. It returns false when the variable is unset.
func (r *reader) boolean(key string) bool {
	s := r.str(key)
	if s == "" {
		return false
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		r.fail(fmt.Errorf("%s: %q is not a boolean (use true or false)", key, s))
		return false
	}
	return v
}

// timestamp parses an RFC 3339 timestamp, such as 2026-11-01T00:00:00Z. It
// returns the zero time when the variable is unset.
func (r *reader) timestamp(key string) time.Time {
	s := r.str(key)
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		r.fail(fmt.Errorf("%s: %q is not an RFC 3339 timestamp such as 2026-11-01T00:00:00Z", key, s))
		return time.Time{}
	}
	return t
}

func (r *reader) level(key string, def slog.Level) slog.Level {
	s := r.str(key)
	if s == "" {
		return def
	}
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	r.fail(fmt.Errorf("%s: %q must be one of debug, info, warn, or error", key, s))
	return def
}

// list splits a comma-separated value into trimmed items. It returns def
// when the variable is unset or has no items.
func (r *reader) list(key string, def []string) []string {
	var out []string
	for item := range strings.SplitSeq(r.str(key), ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

func lower(items []string) []string {
	for i, s := range items {
		items[i] = strings.ToLower(s)
	}
	return items
}

// joinIndented joins errors one per line for a readable startup error.
func joinIndented(errs []error) error {
	msgs := make([]string, len(errs))
	for i, err := range errs {
		msgs[i] = err.Error()
	}
	return errors.New(strings.Join(msgs, "\n  "))
}
