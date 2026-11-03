// Package policy compiles and evaluates the Rego policies that make each
// hook's decision.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// ErrUndefined is returned when the policy defines no result for an input.
var ErrUndefined = errors.New("policy result is undefined")

// Engine is a compiled policy query. It is safe for concurrent use.
type Engine struct {
	query rego.PreparedEvalQuery
}

// Load reads the policy at path and compiles query against it.
func Load(ctx context.Context, path, query string) (*Engine, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	e, err := Compile(ctx, path, string(src), query)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return e, nil
}

// Compile compiles query against the policy source, which must be Rego v1
// and define the rule query refers to, such as data.example.result. name is
// used in error messages.
func Compile(ctx context.Context, name, src, query string) (*Engine, error) {
	pq, err := rego.New(
		rego.Query(query),
		rego.Module(name, src),
		rego.SetRegoVersion(ast.RegoV1),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}

	// a query for a rule the policy doesn't define compiles, but is undefined
	// for every input, so a misspelled package or rule name would fail every
	// event instead of the startup
	if err := checkDefines(name, src, query); err != nil {
		return nil, err
	}
	return &Engine{query: pq}, nil
}

func checkDefines(name, src, query string) error {
	ref, err := ast.ParseRef(query)
	if err != nil {
		return fmt.Errorf("parse query %q: %w", query, err)
	}
	mod, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}
	for _, r := range mod.Rules {
		path := r.Ref()
		if !path.HasPrefix(ast.DefaultRootRef) {
			path = mod.Package.Path.Extend(path)
		}
		// "result.action := ..." defines result too
		if path.HasPrefix(ref) {
			return nil
		}
	}
	pkg, rule := ref[:len(ref)-1], ref[len(ref)-1:]
	return fmt.Errorf("policy does not define %s: it must be in package %s and define a %s rule",
		ref, strings.TrimPrefix(pkg.String(), "data."), rule.String())
}

// Eval evaluates the policy against input and decodes the result into T. It
// returns ErrUndefined when the policy defines no result for the input.
func Eval[T any](ctx context.Context, e *Engine, input any) (T, error) {
	var out T

	rs, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return out, fmt.Errorf("evaluate policy: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return out, ErrUndefined
	}

	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return out, fmt.Errorf("encode policy result: %w", err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("decode policy result: %w", err)
	}
	return out, nil
}
