// Package app wires the function together from its configuration. It is the
// only package that knows about every other one; main and the devtool CLI
// call it, and tests use its options to replace the Cognito client and the
// HTTP client.
package app

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"

	"github.com/cruxstack/cognito-hooks-go/internal/config"
	"github.com/cruxstack/cognito-hooks-go/internal/handler"
	"github.com/cruxstack/cognito-hooks-go/internal/policy"
	"github.com/cruxstack/cognito-hooks-go/internal/postconfirmation"
	"github.com/cruxstack/cognito-hooks-go/internal/presignup"
	"github.com/cruxstack/cognito-hooks-go/internal/sendgrid"
	"github.com/cruxstack/cognito-hooks-go/internal/verify"
)

// Option replaces a dependency that New would otherwise build from the
// configuration and AWS config.
type Option func(*deps)

type deps struct {
	cognito    postconfirmation.CognitoAPI
	httpClient *http.Client
}

// WithCognitoClient replaces the Cognito client the PostConfirmation hook
// calls.
func WithCognitoClient(c postconfirmation.CognitoAPI) Option {
	return func(d *deps) { d.cognito = c }
}

// WithHTTPClient sets the HTTP client used for SendGrid.
func WithHTTPClient(c *http.Client) Option {
	return func(d *deps) { d.httpClient = c }
}

// New builds the Lambda handler. It compiles the policies and creates every
// client up front, so configuration problems surface at startup.
func New(ctx context.Context, cfg *config.Config, awsCfg aws.Config, opts ...Option) (*handler.Handler, error) {
	var d deps
	for _, opt := range opts {
		opt(&d)
	}

	h := &handler.Handler{}

	if cfg.PreSignUp.Enabled {
		hook, err := newPreSignUp(ctx, cfg, &d)
		if err != nil {
			return nil, fmt.Errorf("presignup hook: %w", err)
		}
		h.PreSignUp = hook
	}

	if cfg.PostConfirmation.Enabled {
		hook, err := newPostConfirmation(ctx, cfg, awsCfg, &d)
		if err != nil {
			return nil, fmt.Errorf("postconfirmation hook: %w", err)
		}
		h.PostConfirmation = hook
	}

	return h, nil
}

func newPreSignUp(ctx context.Context, cfg *config.Config, d *deps) (*presignup.Hook, error) {
	pol, err := policy.Load(ctx, cfg.PreSignUp.PolicyPath, presignup.PolicyQuery)
	if err != nil {
		return nil, err
	}

	var verifier verify.Verifier
	if v := cfg.EmailVerification; v.Enabled {
		verifier = verify.SendGrid{
			Client: sendgrid.New(cfg.SendGrid.APIHost, cfg.SendGrid.VerificationAPIKey, d.httpClient),
		}
		if len(v.Allowlist) > 0 {
			verifier = verify.Allowlist{Domains: v.Allowlist, Next: verifier}
		}
	}

	return presignup.New(presignup.Config{
		Policy:         pol,
		Verifier:       verifier,
		VerifyTriggers: cfg.EmailVerification.Triggers,
	})
}

func newPostConfirmation(ctx context.Context, cfg *config.Config, awsCfg aws.Config, d *deps) (*postconfirmation.Hook, error) {
	var pol *policy.Engine
	if path := cfg.PostConfirmation.PolicyPath; path != "" {
		var err error
		if pol, err = policy.Load(ctx, path, postconfirmation.PolicyQuery); err != nil {
			return nil, err
		}
	}

	if d.cognito == nil {
		d.cognito = cip.NewFromConfig(awsCfg)
	}

	return postconfirmation.New(postconfirmation.Config{
		Cognito: d.cognito,
		Policy:  pol,
	})
}
