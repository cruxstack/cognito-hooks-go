package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"net/mail"
	"slices"
	"strings"

	"github.com/cruxstack/cognito-hooks-go/internal/config"
	"github.com/cruxstack/cognito-hooks-go/internal/log"
	"github.com/sendgrid/sendgrid-go"
)

type SendGridEmailEmailAddressValidationCheckResult struct {
}

type SendGridEmailEmailAddressValidationResult struct {
	Email   string  `json:"email"`
	Verdict string  `json:"verdict"`
	Score   float32 `json:"score"`
}

type SendGridEmailEmailAddressValidationResponse struct {
	Result SendGridEmailEmailAddressValidationResult `json:"result"`
}

type SendGridEmailVerifier struct {
	APIHost          string
	APIKey           string
	WhitelistEnabled bool
	Whitelist        *[]string
}

func (v *SendGridEmailVerifier) VerifyEmail(ctx context.Context, email string) (*EmailVerificationResult, error) {
	result, _ := v.VerifyEmailViaWhitelist(ctx, email)
	if result != nil {
		log.Debug("email domain was on whitelist", "email", email)
		return result, nil
	}
	return v.VerifyEmailViaAPI(ctx, email)
}

func (v *SendGridEmailVerifier) VerifyEmailViaWhitelist(ctx context.Context, email string) (*EmailVerificationResult, error) {
	if !v.WhitelistEnabled {
		return nil, nil
	}

	addr, err := mail.ParseAddress(email)
	if err != nil {
		return nil, nil // invalid email format
	}

	at := strings.LastIndex(addr.Address, "@")
	if at == -1 || at == len(addr.Address)-1 {
		return nil, nil // no domain part
	}

	domain := addr.Address[at+1:]
	whitelisted := slices.Contains(*v.Whitelist, strings.ToLower(domain))

	if !whitelisted {
		return nil, nil
	}

	return DefaultValidResult, nil
}

func (v *SendGridEmailVerifier) VerifyEmailViaAPI(ctx context.Context, email string) (*EmailVerificationResult, error) {
	request := sendgrid.GetRequest(v.APIKey, "/v3/validations/email", v.APIHost)
	request.Body = fmt.Appendf(request.Body, `{"email":"%s","source":"cognito"}`, email)
	request.Method = "POST"

	response, err := sendgrid.API(request)
	if err != nil {
		return nil, fmt.Errorf("sendgrid api error: %w", err)
	}

	var payload SendGridEmailEmailAddressValidationResponse

	if err := json.Unmarshal([]byte(response.Body), &payload); err != nil {
		return nil, fmt.Errorf("sendgrid unmarshal error: %w", err)
	}

	result := payload.Result

	return &EmailVerificationResult{
		Score:   result.Score,
		IsValid: result.Verdict != "Invalid",
		Raw:     response.Body,
	}, nil
}

func NewSendGridVerifier(cfg *config.Config) (*SendGridEmailVerifier, error) {
	whitelistEnabled := cfg.EmailVerificationWhitelist != nil && len(*cfg.EmailVerificationWhitelist) > 0

	return &SendGridEmailVerifier{
		WhitelistEnabled: whitelistEnabled,
		Whitelist:        cfg.EmailVerificationWhitelist,
		APIHost:          cfg.SendGridApiHost,
		APIKey:           cfg.SendGridEmailVerificationApiKey,
	}, nil
}
