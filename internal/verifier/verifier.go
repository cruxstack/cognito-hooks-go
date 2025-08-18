package verifier

import "context"

type EmailVerificationResult struct {
	Score        float32 `json:"score"`
	IsValid      bool    `json:"valid"`
	IsDisposable bool    `json:"disposable"`
	IsRoleBased  bool    `json:"role"`
	Raw          string  `json:"raw"`
}

var DefaultValidResult = &EmailVerificationResult{
	Score:        100.0,
	IsValid:      true,
	IsDisposable: false,
	IsRoleBased:  false,
	Raw:          "{}",
}

type EmailVerifier interface {
	VerifyEmail(ctx context.Context, email string) (*EmailVerificationResult, error)
}
