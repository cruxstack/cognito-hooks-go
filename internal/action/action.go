// Package action decodes the actions a policy returns. A policy's result is
// {"actions": [...]}, and each action is a name such as "signup.allow", or an
// object with an "action" name and the action's parameters:
//
//	{"actions": ["signup.allow", {"action": "signup.deny", "reason": "..."}]}
//
// Names are "<resource>.<verb>". Each hook decides which actions it accepts,
// what they mean together, and in which order they run.
package action

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Action is one action from a policy result.
type Action struct {
	// Name is the action's name, lowercased, such as "signup.deny".
	Name string
	// params is the object form, or nil when the action was a string.
	params json.RawMessage
}

// UnmarshalJSON accepts a name or an object with an "action" name.
func (a *Action) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		if err := json.Unmarshal(b, &a.Name); err != nil {
			return err
		}
		a.Name = normalize(a.Name)
		return nil
	}

	var head struct {
		Action *string `json:"action"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return fmt.Errorf(`an action must be a name or an object with an "action" name, not %s`, b)
	}
	if head.Action == nil || normalize(*head.Action) == "" {
		return fmt.Errorf(`an action object must have an "action" name: %s`, b)
	}
	a.Name, a.params = normalize(*head.Action), append(json.RawMessage(nil), b...)
	return nil
}

// MarshalJSON writes the action the way the policy returned it.
func (a Action) MarshalJSON() ([]byte, error) {
	if a.params == nil {
		return json.Marshal(a.Name)
	}
	return a.params, nil
}

// Decode decodes the action's parameters into v, a pointer to a struct.
// Unknown parameters are errors, so a misspelled one isn't ignored; pass a
// pointer to an empty struct for an action that takes none.
func (a Action) Decode(v any) error {
	if a.params == nil {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(a.params, &fields); err != nil {
		return err
	}
	delete(fields, "action")
	rest, err := json.Marshal(fields)
	if err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(rest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("action %q: %w", a.Name, err)
	}
	return nil
}

// Result is a policy's result document.
type Result struct {
	Actions []Action `json:"actions"`
	// V0Action is the top-level "action" of v0 results, decoded only to
	// report a helpful error.
	V0Action json.RawMessage `json:"action,omitempty"`
}

// ErrV0Result is returned for a result in the v0 shape.
var ErrV0Result = errors.New(`policy result uses the v0 shape ({"action": ...}): return {"actions": [...]} instead (see docs/upgrading-to-v1.md)`)

// Check reports a result in the v0 shape.
func (r Result) Check() error {
	if r.V0Action != nil && len(r.Actions) == 0 {
		return ErrV0Result
	}
	return nil
}

// Unknown returns an error for an action the hook doesn't accept.
func Unknown(a Action, hook string, known []string) error {
	return fmt.Errorf("unknown action %q: %s policies can return %s", a.Name, hook, strings.Join(known, ", "))
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
