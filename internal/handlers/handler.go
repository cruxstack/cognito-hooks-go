package handlers

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/cruxstack/cognito-hooks-go/internal/verifier"
)

type Handler interface {
	Handle(ctx context.Context, evt any) (any, error)
}

type PolicyInput struct {
	Trigger           string                                    `json:"trigger"`
	CallerContext     events.CognitoEventUserPoolsCallerContext `json:"callerContext"`
	UserAttributes    map[string]string                         `json:"userAttributes"`
	ClientMetadata    map[string]string                         `json:"clientMetadata"`
	EmailVerification *verifier.EmailVerificationResult         `json:"emailVerification,omitempty"`
}

type PolicyOutput struct {
	Action   string                                        `json:"action"`
	Reason   string                                        `json:"reason,omitempty"`
	Response events.CognitoEventUserPoolsPreSignupResponse `json:"response"`
}
