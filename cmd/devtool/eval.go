package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"github.com/cruxstack/cognito-hooks-go/internal/policy"
	"github.com/cruxstack/cognito-hooks-go/internal/postconfirmation"
	"github.com/cruxstack/cognito-hooks-go/internal/presignup"
	"github.com/cruxstack/cognito-hooks-go/internal/verify"
)

// evalResult is printed for each event.
type evalResult struct {
	Index    int    `json:"index"`
	Trigger  string `json:"trigger"`
	Input    any    `json:"input,omitempty"`
	Decision any    `json:"decision,omitempty"`
	// Outcome summarizes what the hook would do.
	Outcome string `json:"outcome"`
	Error   string `json:"error,omitempty"`
}

type evalOptions struct {
	presignup        *policy.Engine
	postconfirmation *policy.Engine
	verification     *verify.Result
	verifyTriggers   []string
}

func evalCmd(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	eventsPath := fs.String("events", "", "JSON file with an event or an array of events (required)")
	preSignUpPolicy := fs.String("presignup-policy", "", "PreSignUp policy (required for PreSignUp events)")
	postConfirmationPolicy := fs.String("postconfirmation-policy", "", "PostConfirmation policy (optional; without one every native user is scrambled)")
	verdict := fs.String("verdict", "", "give PreSignUp policies an email verification result with this verdict: Valid, Risky, or Invalid")
	verifyTriggers := fs.String("verify-triggers", presignup.TriggerSignUp, "comma-separated trigger sources -verdict applies to, as in APP_EMAIL_VERIFICATION_FOR_TRIGGER_SOURCES")
	showInput := fs.Bool("show-input", false, "print the policy input for each event")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *eventsPath == "" {
		fs.Usage()
		return errors.New("-events is required")
	}

	slog.SetDefault(newLogger(io.Discard, slog.LevelError))

	events, err := readEvents(*eventsPath)
	if err != nil {
		return err
	}

	var o evalOptions
	if *preSignUpPolicy != "" {
		if o.presignup, err = policy.Load(ctx, *preSignUpPolicy, presignup.PolicyQuery); err != nil {
			return err
		}
	}
	if *postConfirmationPolicy != "" {
		if o.postconfirmation, err = policy.Load(ctx, *postConfirmationPolicy, postconfirmation.PolicyQuery); err != nil {
			return err
		}
	}
	if *verdict != "" {
		if o.verification, err = syntheticVerification(*verdict); err != nil {
			return err
		}
		for t := range strings.SplitSeq(*verifyTriggers, ",") {
			o.verifyTriggers = append(o.verifyTriggers, strings.TrimSpace(t))
		}
	}

	enc := newEncoder(out)
	failed := 0
	for i, raw := range events {
		res := evalResult{Index: i}
		evalEvent(ctx, raw, &res, o)
		if !*showInput {
			res.Input = nil
		}
		if res.Error != "" {
			res.Outcome, failed = "error", failed+1
		}
		if err := enc.Encode(res); err != nil {
			return err
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d events failed", failed, len(events))
	}
	return nil
}

func evalEvent(ctx context.Context, raw json.RawMessage, res *evalResult, o evalOptions) {
	var h header
	if err := json.Unmarshal(raw, &h); err != nil {
		res.Error = fmt.Sprintf("decode event: %v", err)
		return
	}
	res.Trigger = h.TriggerSource

	switch {
	case strings.HasPrefix(h.TriggerSource, presignup.TriggerPrefix):
		var e presignup.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			res.Error = fmt.Sprintf("decode event: %v", err)
			return
		}
		if o.presignup == nil {
			res.Error = "PreSignUp event but no -presignup-policy"
			return
		}
		var v *verify.Result
		if e.Request.UserAttributes["email"] != "" && slices.Contains(o.verifyTriggers, e.TriggerSource) {
			v = o.verification
		}
		in := presignup.NewPolicyInput(&e, v)
		res.Input = in

		d, err := presignup.Decide(ctx, o.presignup, in)
		if err != nil {
			res.Error = err.Error()
			return
		}
		res.Decision = d
		res.Outcome = preSignUpOutcome(d)

	case strings.HasPrefix(h.TriggerSource, postconfirmation.TriggerPrefix):
		var e postconfirmation.Event
		if err := json.Unmarshal(raw, &e); err != nil {
			res.Error = fmt.Sprintf("decode event: %v", err)
			return
		}
		if e.Request.UserAttributes["cognito:user_status"] == postconfirmation.UserStatusExternalProvider {
			res.Outcome = "skip: federated user"
			return
		}
		if o.postconfirmation == nil {
			res.Outcome = postconfirmation.ActionScramble
			return
		}
		in := postconfirmation.NewPolicyInput(&e)
		res.Input = in

		d, err := postconfirmation.Decide(ctx, o.postconfirmation, in)
		if err != nil {
			// the hook would scramble anyway, but the policy needs fixing
			res.Error = err.Error() + " (the hook scrambles the password when the policy fails)"
			return
		}
		res.Decision = d
		res.Outcome = d.Action
		if d.Reason != "" {
			res.Outcome += ": " + d.Reason
		}

	default:
		res.Error = "unsupported trigger source"
	}
}

// preSignUpOutcome is "deny: <reason>", or "allow" followed by the flags the
// policy set.
func preSignUpOutcome(d *presignup.Decision) string {
	if d.Action == presignup.ActionDeny {
		return "deny: " + d.Reason
	}
	var flags []string
	for name, set := range map[string]bool{
		"autoConfirmUser": d.Response.AutoConfirmUser,
		"autoVerifyEmail": d.Response.AutoVerifyEmail,
		"autoVerifyPhone": d.Response.AutoVerifyPhone,
	} {
		if set {
			flags = append(flags, name)
		}
	}
	if len(flags) == 0 {
		return "allow"
	}
	slices.Sort(flags)
	return "allow: " + strings.Join(flags, ", ")
}

// syntheticVerification returns a SendGrid-like result with the verdict.
func syntheticVerification(verdict string) (*verify.Result, error) {
	scores := map[string]float64{verify.VerdictValid: 0.95, verify.VerdictRisky: 0.5, verify.VerdictInvalid: 0.05}
	for v, score := range scores {
		if strings.EqualFold(v, verdict) {
			return &verify.Result{
				Provider: verify.ProviderSendGrid,
				Valid:    v != verify.VerdictInvalid,
				Verdict:  v,
				Score:    score,
				Raw:      "{}",
			}, nil
		}
	}
	return nil, fmt.Errorf("-verdict %q must be Valid, Risky, or Invalid", verdict)
}
