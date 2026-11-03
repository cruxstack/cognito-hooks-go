// Package policy compiles and evaluates the Rego policies that make each
// hook's decision.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

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

// Compile compiles query against the policy source, which must be Rego v1.
// name is used in error messages.
func Compile(ctx context.Context, name, src, query string) (*Engine, error) {
	pq, err := rego.New(
		rego.Query(query),
		rego.Module(name, src),
		rego.SetRegoVersion(ast.RegoV1),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	return &Engine{query: pq}, nil
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
