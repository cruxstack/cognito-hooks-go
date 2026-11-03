package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const query = "data.example.result"

type result struct {
	Admin bool `json:"admin"`
}

func TestEval(t *testing.T) {
	ctx := context.Background()
	e, err := Compile(ctx, "example.rego", `
package example

result := {"admin": input.user == "admin"} if input.user
`, query)
	if err != nil {
		t.Fatal(err)
	}

	for user, want := range map[string]bool{"admin": true, "guest": false} {
		got, err := Eval[result](ctx, e, map[string]any{"user": user})
		if err != nil {
			t.Fatal(err)
		}
		if got.Admin != want {
			t.Errorf("user %q: admin = %v, want %v", user, got.Admin, want)
		}
	}

	if _, err := Eval[result](ctx, e, map[string]any{}); !errors.Is(err, ErrUndefined) {
		t.Errorf("missing user: err = %v, want ErrUndefined", err)
	}
}

func TestEval_ConflictingRulesIsAnError(t *testing.T) {
	ctx := context.Background()
	e, err := Compile(ctx, "example.rego", `
package example

result := {"admin": true}
result := {"admin": false} if input.conflict
`, query)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Eval[result](ctx, e, map[string]any{"conflict": true}); err == nil || errors.Is(err, ErrUndefined) {
		t.Errorf("err = %v, want an evaluation error", err)
	}
}

func TestEval_ResultOfWrongShapeIsAnError(t *testing.T) {
	ctx := context.Background()
	e, err := Compile(ctx, "example.rego", "package example\n\nresult := \"not an object\"\n", query)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Eval[result](ctx, e, nil); err == nil {
		t.Error("expected a decode error")
	}
}

// A misspelled package or rule name must fail at startup, not on every
// event.
func TestCompile_RequiresTheQueriedRule(t *testing.T) {
	tests := map[string]string{
		"wrong package": "package examples\n\nresult := {\"admin\": true}\n",
		"wrong rule":    "package example\n\nresults := {\"admin\": true}\n",
		"no rules":      "package example\n",
	}
	for name, src := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Compile(context.Background(), "p.rego", src, query)
			if err == nil || !strings.Contains(err.Error(), "policy does not define data.example.result") {
				t.Errorf("err = %v, want an error naming the missing rule", err)
			}
		})
	}

	ok := map[string]string{
		"default only": "package example\n\ndefault result := {}\n",
		"ref head":     "package example\n\nresult.admin := true\n",
	}
	for name, src := range ok {
		e, err := Compile(context.Background(), "p.rego", src, query)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if _, err := Eval[result](context.Background(), e, nil); err != nil {
			t.Errorf("%s: Eval() = %v", name, err)
		}
	}
}

func TestCompile_RequiresRegoV1(t *testing.T) {
	// rego v0: rule bodies without "if"
	_, err := Compile(context.Background(), "v0.rego", "package example\n\nresult { true }\n", query)
	if err == nil {
		t.Fatal("expected a compile error for rego v0 syntax")
	}
}

func TestLoad(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	path := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(path, []byte("package example\n\nresult := {\"admin\": true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, path, query); err != nil {
		t.Errorf("Load() = %v", err)
	}

	if _, err := Load(ctx, filepath.Join(dir, "missing.rego"), query); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: err = %v, want ErrNotExist", err)
	}

	bad := filepath.Join(dir, "bad.rego")
	if err := os.WriteFile(bad, []byte("package example\n\nresult := \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, bad, query); err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("syntax error: err = %v, want an error naming the file", err)
	}
}
