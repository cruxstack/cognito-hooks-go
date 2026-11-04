// Package app wires the function together from its configuration. It is the
// only package that knows about every other one; main and the devtool CLI
// call it, and tests use its options to replace the Cognito, DynamoDB, and
// HTTP clients.
package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/cruxstack/cognito-hooks-go/internal/config"
	"github.com/cruxstack/cognito-hooks-go/internal/handler"
	"github.com/cruxstack/cognito-hooks-go/internal/policy"
	"github.com/cruxstack/cognito-hooks-go/internal/postconfirmation"
	"github.com/cruxstack/cognito-hooks-go/internal/preauthentication"
	"github.com/cruxstack/cognito-hooks-go/internal/presignup"
	"github.com/cruxstack/cognito-hooks-go/internal/rotation"
	"github.com/cruxstack/cognito-hooks-go/internal/sendgrid"
	"github.com/cruxstack/cognito-hooks-go/internal/verify"
)

// AWS SDK retries. Cognito waits at most 5 seconds for the function, and the
// SDK's default (3 attempts, up to 20 seconds apart) would outlast it, so each
// call is retried at most once, soon after the first attempt. Under sustained
// throttling more retries would only add load.
const (
	MaxAttempts = 2
	MaxBackoff  = 200 * time.Millisecond
)

// CognitoAPI is the part of the Cognito API the hooks call.
type CognitoAPI interface {
	postconfirmation.CognitoAPI
	preauthentication.CognitoAPI
}

// Option replaces a dependency that New would otherwise build from the
// configuration and AWS config.
type Option func(*deps)

type deps struct {
	cognito    CognitoAPI
	dynamodb   rotation.DynamoDBAPI
	httpClient *http.Client
}

// WithCognitoClient replaces the Cognito client the PostConfirmation and
// PreAuthentication hooks call.
func WithCognitoClient(c CognitoAPI) Option {
	return func(d *deps) { d.cognito = c }
}

// WithDynamoDBClient replaces the DynamoDB client that reads and writes
// rotation records.
func WithDynamoDBClient(c rotation.DynamoDBAPI) Option {
	return func(d *deps) { d.dynamodb = c }
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

	if cfg.PreAuthentication.Enabled {
		hook, err := newPreAuthentication(ctx, cfg, awsCfg, &d)
		if err != nil {
			return nil, fmt.Errorf("preauthentication hook: %w", err)
		}
		h.PreAuthentication = hook
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

	var rotations rotation.Store
	if table := cfg.PostConfirmation.RotationTable; table != "" {
		rotations = rotation.DynamoDB{Client: d.dynamoDB(awsCfg), Table: table}
	}

	return postconfirmation.New(postconfirmation.Config{
		Cognito:   d.cognitoIDP(awsCfg),
		Policy:    pol,
		Rotations: rotations,
	})
}

func newPreAuthentication(ctx context.Context, cfg *config.Config, awsCfg aws.Config, d *deps) (*preauthentication.Hook, error) {
	var pol *policy.Engine
	if path := cfg.PreAuthentication.PolicyPath; path != "" {
		var err error
		if pol, err = policy.Load(ctx, path, preauthentication.PolicyQuery); err != nil {
			return nil, err
		}
	}

	return preauthentication.New(preauthentication.Config{
		Cognito:      d.cognitoIDP(awsCfg),
		Rotations:    rotation.DynamoDB{Client: d.dynamoDB(awsCfg), Table: cfg.PreAuthentication.RotationTable},
		RotateBefore: cfg.PreAuthentication.RotateBefore,
		Policy:       pol,
	})
}

// cognitoIDP returns the Cognito client, creating it on first use so the
// hooks share one.
func (d *deps) cognitoIDP(awsCfg aws.Config) CognitoAPI {
	if d.cognito == nil {
		d.cognito = cip.NewFromConfig(awsCfg, func(o *cip.Options) { o.Retryer = newRetryer() })
	}
	return d.cognito
}

// dynamoDB returns the DynamoDB client, creating it on first use so the
// hooks share one.
func (d *deps) dynamoDB(awsCfg aws.Config) rotation.DynamoDBAPI {
	if d.dynamodb == nil {
		d.dynamodb = dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { o.Retryer = newRetryer() })
	}
	return d.dynamodb
}

func newRetryer() aws.Retryer {
	return retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = MaxAttempts
		o.MaxBackoff = MaxBackoff
	})
}
