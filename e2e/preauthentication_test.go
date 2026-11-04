package e2e

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/cruxstack/cognito-hooks-go/internal/app"
	"github.com/cruxstack/cognito-hooks-go/internal/config"
)

const (
	user1 = "8a1b2c3d-0000-4000-8000-000000000001"
	user2 = "8a1b2c3d-0000-4000-8000-000000000002"
)

// preAuthVars enables the PreAuthentication hook with password rotation and
// a cutoff, plus extra.
func preAuthVars(cutoff string, extra ...string) map[string]string {
	vars := map[string]string{
		"APP_PREAUTHENTICATION_ENABLED":                   "true",
		"APP_PREAUTHENTICATION_PASSWORD_ROTATION_ENABLED": "true",
		"APP_PREAUTHENTICATION_ROTATE_BEFORE":             cutoff,
		"APP_PREAUTHENTICATION_ROTATION_TABLE":            "rotations",
	}
	for i := 0; i+1 < len(extra); i += 2 {
		vars[extra[i]] = extra[i+1]
	}
	return vars
}

// record stores a rotation record for a user.
func (f *fakeDynamoDB) record(sub string, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items["rotations/"+sub] = map[string]ddbtypes.AttributeValue{
		"sub":         &ddbtypes.AttributeValueMemberS{Value: sub},
		"replaced_at": &ddbtypes.AttributeValueMemberS{Value: at.Format(time.RFC3339Nano)},
	}
}

// Password rotation is off by default: the hook needs no other setting, and
// it calls neither Cognito nor DynamoDB.
func TestPreAuthentication_PasswordRotationIsOffByDefault(t *testing.T) {
	for name, vars := range map[string]map[string]string{
		"default": {"APP_PREAUTHENTICATION_ENABLED": "true"},
		"turned off with its settings left": {
			"APP_PREAUTHENTICATION_ENABLED":                   "true",
			"APP_PREAUTHENTICATION_PASSWORD_ROTATION_ENABLED": "false",
			"APP_PREAUTHENTICATION_ROTATE_BEFORE":             "2026-11-01T00:00:00Z",
			"APP_PREAUTHENTICATION_ROTATION_TABLE":            "rotations",
			"APP_PREAUTHENTICATION_POLICY_PATH":               policies + "preauthentication/skip-users.rego",
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, vars)
			resp := e.mustHandle(signIn(user1, "CONFIRMED"))
			if resp["triggerSource"] != "PreAuthentication_Authentication" {
				t.Errorf("response = %v, want the request event", resp)
			}
			e.mustHandle(preAuthenticationEvent("emma", map[string]string{"email": "emma@example.com"}, false))
			if got := len(e.cognito.replaced()); got != 0 || e.cognito.lookups != 0 || e.dynamodb.gets != 0 || e.dynamodb.putCount != 0 {
				t.Errorf("replacements %d, lookups %d, record reads %d, writes %d; want none",
					got, e.cognito.lookups, e.dynamodb.gets, e.dynamodb.putCount)
			}
		})
	}
}

func TestPreAuthentication_ReplacesAStalePasswordOnce(t *testing.T) {
	e := newEnv(t, preAuthVars("2026-11-01T00:00:00Z"))
	start := time.Now()

	for range 2 {
		resp := e.mustHandle(signIn(user1, "CONFIRMED"))
		if resp["triggerSource"] != "PreAuthentication_Authentication" || resp["userName"] != user1 {
			t.Errorf("response = %v, want the request event", resp)
		}
	}

	if got := e.cognito.replaced(); len(got) != 1 || got[0] != "us-east-1_EXAMPLE/"+user1 {
		t.Errorf("replaced = %v, want the user's password replaced once", got)
	}
	if at, ok := e.dynamodb.replacedAt("rotations", user1); !ok || at.Before(start) {
		t.Errorf("record = %v, %v; want the replacement recorded", at, ok)
	}
}

// Moving the cutoff later replaces every password once more.
func TestPreAuthentication_LaterCutoffReplacesAgain(t *testing.T) {
	ddb := newFakeDynamoDB()
	ddb.record(user1, time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))

	e := newEnvWith(t, preAuthVars("2026-11-01T00:00:00Z"), ddb)
	e.mustHandle(signIn(user1, "CONFIRMED"))
	if got := len(e.cognito.replaced()); got != 0 {
		t.Fatalf("replaced %d passwords, want 0: the record is after the cutoff", got)
	}

	e = newEnvWith(t, preAuthVars("2026-11-03T00:00:00Z"), ddb)
	e.mustHandle(signIn(user1, "CONFIRMED"))
	if got := len(e.cognito.replaced()); got != 1 {
		t.Errorf("replaced %d passwords, want 1 after moving the cutoff", got)
	}
}

func TestPreAuthentication_KeepsPasswordsItMustNotReplace(t *testing.T) {
	e := newEnv(t, preAuthVars("2026-11-01T00:00:00Z"))

	e.mustHandle(preAuthenticationEvent("mallory@example.com", map[string]string{}, true))
	e.mustHandle(signIn(user1, "EXTERNAL_PROVIDER"))
	e.mustHandle(signIn(user2, "UNCONFIRMED"))

	if got := len(e.cognito.replaced()); got != 0 {
		t.Errorf("replaced %d passwords, want 0", got)
	}
	if e.cognito.lookups != 0 || e.dynamodb.gets != 0 || e.dynamodb.putCount != 0 {
		t.Errorf("lookups %d, record reads %d, writes %d; want none", e.cognito.lookups, e.dynamodb.gets, e.dynamodb.putCount)
	}
}

func TestPreAuthentication_PolicySkipsTestUsers(t *testing.T) {
	e := newEnv(t, preAuthVars("2026-11-01T00:00:00Z",
		"APP_PREAUTHENTICATION_POLICY_PATH", policies+"preauthentication/skip-users.rego"))

	e.mustHandle(signIn("8a1b2c3d-0000-4000-8000-000000000005", "CONFIRMED"))
	e.mustHandle(preAuthenticationEvent("e2e-runner", map[string]string{
		"sub":                 "8a1b2c3d-0000-4000-8000-000000000007",
		"cognito:user_status": "CONFIRMED",
	}, false))
	if got := len(e.cognito.replaced()); got != 0 {
		t.Errorf("replaced %d passwords, want 0 for the test users", got)
	}

	e.mustHandle(signIn(user1, "CONFIRMED"))
	if got := len(e.cognito.replaced()); got != 1 {
		t.Errorf("replaced %d passwords, want 1", got)
	}
}

// AdminSetUserPassword shares a quota of 30 requests per second. When it is
// throttled, the sign-in is rejected with a message for the user, so the old
// password is never checked.
func TestPreAuthentication_ThrottlingRejectsTheSignIn(t *testing.T) {
	e := newEnv(t, preAuthVars("2026-11-01T00:00:00Z"))
	e.cognito.err = &types.TooManyRequestsException{Message: aws.String("Rate exceeded")}

	_, err := e.handle(signIn(user1, "CONFIRMED"))
	if err == nil || err.Error() != "Sign-in is temporarily unavailable. Try again in a moment." {
		t.Errorf("err = %v, want the generic message for users", err)
	}
	if _, ok := e.dynamodb.replacedAt("rotations", user1); ok {
		t.Error("a failed replacement must not be recorded")
	}

	// the next sign-in tries again
	e.cognito.err = nil
	e.mustHandle(signIn(user1, "CONFIRMED"))
	if _, ok := e.dynamodb.replacedAt("rotations", user1); !ok {
		t.Error("want the replacement recorded once the quota allows it")
	}
}

func TestPreAuthentication_RotationTableFailures(t *testing.T) {
	t.Run("unreadable record replaces", func(t *testing.T) {
		ddb := newFakeDynamoDB()
		ddb.record(user1, time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
		ddb.getErr = errors.New("ProvisionedThroughputExceededException")
		e := newEnvWith(t, preAuthVars("2026-11-01T00:00:00Z"), ddb)

		e.mustHandle(signIn(user1, "CONFIRMED"))
		if got := len(e.cognito.replaced()); got != 1 {
			t.Errorf("replaced %d passwords, want 1", got)
		}
	})

	t.Run("unwritable record allows the sign-in", func(t *testing.T) {
		e := newEnv(t, preAuthVars("2026-11-01T00:00:00Z"))
		e.dynamodb.putErr = errors.New("AccessDeniedException")

		e.mustHandle(signIn(user1, "CONFIRMED"))
		e.mustHandle(signIn(user1, "CONFIRMED"))
		if got := len(e.cognito.replaced()); got != 2 {
			t.Errorf("replaced %d passwords, want 2: without a record, each sign-in replaces it", got)
		}
	})
}

// A status missing from the event is looked up, not guessed.
func TestPreAuthentication_LooksUpAMissingStatus(t *testing.T) {
	e := newEnv(t, preAuthVars("2026-11-01T00:00:00Z"))
	e.cognito.users = map[string]*cip.AdminGetUserOutput{
		"emma": {
			UserStatus:     types.UserStatusTypeConfirmed,
			UserAttributes: []types.AttributeType{{Name: aws.String("sub"), Value: aws.String(user1)}},
		},
		"olivia": {UserStatus: types.UserStatusTypeExternalProvider},
	}

	e.mustHandle(preAuthenticationEvent("emma", map[string]string{"email": "emma@example.com"}, false))
	e.mustHandle(preAuthenticationEvent("olivia", map[string]string{"email": "olivia@example.com"}, false))
	if got := e.cognito.replaced(); len(got) != 1 || got[0] != "us-east-1_EXAMPLE/emma" {
		t.Errorf("replaced = %v, want only the confirmed user's password", got)
	}
	if _, ok := e.dynamodb.replacedAt("rotations", user1); !ok {
		t.Error("want the replacement recorded under the looked-up sub")
	}

	// a user who can't be looked up can't sign in
	if _, err := e.handle(preAuthenticationEvent("liam", map[string]string{}, false)); err == nil || !strings.Contains(err.Error(), "temporarily unavailable") {
		t.Errorf("err = %v, want the sign-in rejected", err)
	}
}

// With the rotation table, PostConfirmation records its replacements, so a
// newly confirmed user doesn't get another new password at their first
// sign-in.
func TestPreAuthentication_PostConfirmationRecordsReplacements(t *testing.T) {
	e := newEnv(t, preAuthVars("2026-11-01T00:00:00Z",
		"APP_POSTCONFIRMATION_ENABLED", "true",
		"APP_POSTCONFIRMATION_ROTATION_TABLE", "rotations"))

	e.mustHandle(postConfirmationEvent("PostConfirmation_ConfirmSignUp", "1example23456789", "CONFIRMED"))
	e.mustHandle(signIn(user1, "CONFIRMED"))
	if got := len(e.cognito.replaced()); got != 1 {
		t.Errorf("replaced %d passwords, want 1: PostConfirmation's replacement is recorded", got)
	}
}

// Without its rotation table setting, PostConfirmation records nothing.
func TestPreAuthentication_PostConfirmationWithoutTheTable(t *testing.T) {
	e := newEnv(t, preAuthVars("2026-11-01T00:00:00Z", "APP_POSTCONFIRMATION_ENABLED", "true"))

	e.mustHandle(postConfirmationEvent("PostConfirmation_ConfirmSignUp", "1example23456789", "CONFIRMED"))
	e.mustHandle(signIn(user1, "CONFIRMED"))
	if got := len(e.cognito.replaced()); got != 2 {
		t.Errorf("replaced %d passwords, want 2", got)
	}
}

// A policy that fails at evaluation time still replaces a stale password.
func TestPreAuthentication_BrokenPolicyStillReplaces(t *testing.T) {
	e := newEnv(t, preAuthVars("2026-11-01T00:00:00Z",
		"APP_PREAUTHENTICATION_POLICY_PATH", writePolicy(t, "package cognito_hook_preauthentication\n\nresult := \"skip\"\n")))
	e.mustHandle(signIn(user1, "CONFIRMED"))
	if got := len(e.cognito.replaced()); got != 1 {
		t.Errorf("replaced %d passwords, want 1", got)
	}
}

func TestPreAuthentication_StartupErrors(t *testing.T) {
	tests := map[string]struct {
		vars map[string]string
		want string
	}{
		"misspelled policy": {
			vars: preAuthVars("2026-11-01T00:00:00Z", "APP_PREAUTHENTICATION_POLICY_PATH",
				writePolicy(t, "package cognito_hook_pre_authentication\n\nresult := {\"actions\": [\"password.skip\"]}\n")),
			want: "does not define data.cognito_hook_preauthentication.result",
		},
		"no cutoff":         {vars: preAuthVars(""), want: "APP_PREAUTHENTICATION_ROTATE_BEFORE is required"},
		"cutoff not passed": {vars: preAuthVars("2999-01-01T00:00:00Z"), want: "is in the future"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, err := config.Load(func(k string) (string, bool) { v, ok := tt.vars[k]; return v, ok })
			if err == nil {
				_, err = app.New(context.Background(), cfg, aws.Config{}, app.WithCognitoClient(&fakeCognito{}), app.WithDynamoDBClient(newFakeDynamoDB()))
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}
