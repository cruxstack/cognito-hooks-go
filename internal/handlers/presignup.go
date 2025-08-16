package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/aws/aws-lambda-go/events"
	"github.com/cruxstack/cognito-hooks-go/internal/config"
	"github.com/cruxstack/cognito-hooks-go/internal/log"
	"github.com/cruxstack/cognito-hooks-go/internal/opa"
	"github.com/cruxstack/cognito-hooks-go/internal/verifier"
)

type PreSignupHandler struct {
	Config        *config.Config
	PolicyQuery   *string
	Policy        *string
	EmailVerifier verifier.EmailVerifier
}

func NewPreSignupHandler(cfg *config.Config) (*PreSignupHandler, error) {
	if cfg.AppPolicyPath == "" {
		return nil, fmt.Errorf("policy path is empty")
	}
	policyQuery := "data.cognito_hook_presignup.result"
	policy, err := opa.ReadPolicy(cfg.AppPolicyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy at path: %s", cfg.AppPolicyPath)
	}

	verifier, err := verifier.NewSendGridVerifier(cfg)
	if err != nil {
		return nil, fmt.Errorf("sendgrid init error: %w", err)
	}
	return &PreSignupHandler{
		Config:        cfg,
		PolicyQuery:   &policyQuery,
		Policy:        policy,
		EmailVerifier: verifier,
	}, nil
}

func (h *PreSignupHandler) Handle(ctx context.Context, evt events.CognitoEventUserPoolsPreSignup) (events.CognitoEventUserPoolsPreSignup, error) {
	if h.Config.DebugEnabled {
		evtJSON, err := json.Marshal(evt)
		if err != nil {
			log.Warn("failed to marshal triggered event", "error", err)
		} else {
			log.Debug(string(evtJSON))
		}
	}

	verificationData := h.VerifyEmail(ctx, &evt)

	input := &PolicyInput{
		Trigger:           evt.TriggerSource,
		CallerContext:     evt.CallerContext,
		UserAttributes:    evt.Request.UserAttributes,
		ClientMetadata:    evt.Request.ClientMetadata,
		EmailVerification: verificationData,
	}

	output, err := opa.EvaluatePolicy[PolicyOutput](ctx, h.Policy, h.PolicyQuery, input)
	if err != nil {
		log.Error("failed to evaluate policy", "error", err)
		return evt, nil
	}

	if output.Action == "deny" {
		return evt, errors.New(output.Reason)
	}

	evt.Response = output.Response
	return evt, nil
}

func (h *PreSignupHandler) VerifyEmail(ctx context.Context, evt *events.CognitoEventUserPoolsPreSignup) *verifier.EmailVerificationResult {
	var verificationData *verifier.EmailVerificationResult

	if !h.Config.EmailVerificationEnabled {
		return nil // skip verification when disabled
	}

	if !slices.Contains(*h.Config.EmailVerificationForTriggerSources, evt.TriggerSource) {
		return nil // skip verifiction if source not in list
	}

	email := evt.Request.UserAttributes["email"]
	if email == "" {
		log.Info("skipping email verification because no email address was found")
		return nil
	}

	verificationData, err := h.EmailVerifier.VerifyEmail(ctx, email)
	if err != nil {
		log.Warn("sendgrid verify email error", "error", err)
	}

	return verificationData
}
