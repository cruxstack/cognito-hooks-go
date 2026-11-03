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
	postConfirmationPolicy := fs.String("postconfirmation-policy", "", "PostConfirmation policy (optional; without one every native user's password is replaced)")
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
		in := postconfirmation.NewPolicyInput(&e)
		res.Input = in

		d := postconfirmation.DefaultDecision()
		if o.postconfirmation != nil {
			var err error
			if d, err = postconfirmation.Decide(ctx, o.postconfirmation, in); err != nil {
				// the hook would apply the default actions, but the policy
				// needs fixing
				res.Error = err.Error() + " (the hook applies the default actions when the policy fails)"
				return
			}
		}
		res.Decision = d
		res.Outcome = postConfirmationOutcome(&e, d)

	default:
		res.Error = "unsupported trigger source"
	}
}

// preSignUpOutcome is "signup.deny: <reason>", or "signup.allow" followed by
// the actions that set Cognito's flags.
func preSignUpOutcome(d *presignup.Decision) string {
	if !d.Allowed {
		return presignup.ActionDeny + ": " + d.Reason
	}
	out := []string{presignup.ActionAllow}
	for _, f := range []struct {
		set  bool
		name string
	}{
		{d.Response.AutoConfirmUser, presignup.ActionConfirmUser},
		{d.Response.AutoVerifyEmail, presignup.ActionVerifyEmail},
		{d.Response.AutoVerifyPhone, presignup.ActionVerifyPhone},
	} {
		if f.set {
			out = append(out, f.name)
		}
	}
	return strings.Join(out, ", ")
}

// postConfirmationOutcome is "password.replace", or "password.skip: <reason>".
// Federated users have no Cognito password, so the password is never
// replaced for them.
func postConfirmationOutcome(e *postconfirmation.Event, d *postconfirmation.Decision) string {
	switch {
	case e.Request.UserAttributes["cognito:user_status"] == postconfirmation.UserStatusExternalProvider:
		return postconfirmation.ActionSkipPassword + ": federated user"
	case !d.ReplacePassword && d.Reason != "":
		return postconfirmation.ActionSkipPassword + ": " + d.Reason
	case !d.ReplacePassword:
		return postconfirmation.ActionSkipPassword
	}
	return postconfirmation.ActionReplacePassword
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
