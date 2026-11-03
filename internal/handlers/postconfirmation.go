package handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/cruxstack/cognito-hooks-go/internal/config"
	"github.com/cruxstack/cognito-hooks-go/internal/log"
	"github.com/cruxstack/cognito-hooks-go/internal/opa"
	"github.com/cruxstack/cognito-hooks-go/internal/password"
)

// PasswordLength is the length of the random password set on each user.
const PasswordLength = 64

// PasswordSetter is the part of the Cognito API that the hook calls.
type PasswordSetter interface {
	AdminSetUserPassword(ctx context.Context, params *cip.AdminSetUserPasswordInput, optFns ...func(*cip.Options)) (*cip.AdminSetUserPasswordOutput, error)
}

// PostConfirmationPolicyOutput is the result of the optional policy.
type PostConfirmationPolicyOutput struct {
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
}

// PostConfirmationHandler replaces the password of every newly confirmed
// native user with a random one that nobody knows, so the user signs in with
// passwordless factors only. It also runs after a forgotten-password reset,
// replacing the password the user just chose.
type PostConfirmationHandler struct {
	Config      *config.Config
	PolicyQuery *string
	Policy      *string
	Cognito     PasswordSetter
}

func NewPostConfirmationHandler(cfg *config.Config, cognito PasswordSetter) (*PostConfirmationHandler, error) {
	h := &PostConfirmationHandler{Config: cfg, Cognito: cognito}
	if cfg.AppPolicyPath == "" {
		return h, nil
	}

	policy, err := opa.ReadPolicy(cfg.AppPolicyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy at path: %s", cfg.AppPolicyPath)
	}
	query := "data.cognito_hook_postconfirmation.result"
	h.Policy = policy
	h.PolicyQuery = &query
	return h, nil
}

// Handle never returns an error: Cognito has already confirmed the user, so
// failing would only show the user an error without undoing anything.
func (h *PostConfirmationHandler) Handle(ctx context.Context, evt events.CognitoEventUserPoolsPostConfirmation) (events.CognitoEventUserPoolsPostConfirmation, error) {
	if h.Config.DebugEnabled {
		evtJSON, err := json.Marshal(evt)
		if err != nil {
			log.Warn("failed to marshal triggered event", "error", err)
		} else {
			log.Debug(string(evtJSON))
		}
	}

	logger := log.With("trigger", evt.TriggerSource, "sub", evt.Request.UserAttributes["sub"])

	if evt.Request.UserAttributes["cognito:user_status"] == "EXTERNAL_PROVIDER" {
		logger.Info("password scramble skipped", "reason", "federated user")
		return evt, nil
	}

	if skip, reason := h.skippedByPolicy(ctx, &evt); skip {
		logger.Info("password scramble skipped", "reason", reason)
		return evt, nil
	}

	pw, err := password.Generate(PasswordLength)
	if err != nil {
		logger.Error("password scramble failed", "error", err)
		return evt, nil
	}

	_, err = h.Cognito.AdminSetUserPassword(ctx, &cip.AdminSetUserPasswordInput{
		UserPoolId: aws.String(evt.UserPoolID),
		Username:   aws.String(evt.UserName),
		Password:   aws.String(pw),
		Permanent:  true,
	})
	if err != nil {
		logger.Error("password scramble failed", "error", err)
		return evt, nil
	}

	logger.Info("password scrambled")
	return evt, nil
}

// skippedByPolicy reports whether the optional policy exempts this user. A
// policy error scrambles the password anyway.
func (h *PostConfirmationHandler) skippedByPolicy(ctx context.Context, evt *events.CognitoEventUserPoolsPostConfirmation) (bool, string) {
	if h.Policy == nil {
		return false, ""
	}

	input := &PolicyInput{
		Trigger:        evt.TriggerSource,
		CallerContext:  evt.CallerContext,
		UserAttributes: evt.Request.UserAttributes,
		ClientMetadata: evt.Request.ClientMetadata,
	}

	output, err := opa.EvaluatePolicy[PostConfirmationPolicyOutput](ctx, h.Policy, h.PolicyQuery, input)
	if err != nil {
		log.Error("failed to evaluate policy", "error", err)
		return false, ""
	}

	return output.Action == "skip", output.Reason
}
