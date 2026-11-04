// Command bootstrap is the AWS Lambda function for Amazon Cognito user pool
// hooks (PreSignUp, PostConfirmation, and PreAuthentication). Build it for
// the provided.al2023 runtime:
//
//	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags lambda.norpc -o bootstrap .
package main

import (
	"context"
	"log/slog"
	"os"
	"runtime/debug"

	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/cruxstack/cognito-hooks-go/internal/app"
	"github.com/cruxstack/cognito-hooks-go/internal/config"
	"github.com/cruxstack/cognito-hooks-go/internal/logging"
)

// version is set at build time with -ldflags "-X main.version=v1.0.0".
var version = "dev"

func main() {
	var level slog.LevelVar
	slog.SetDefault(slog.New(logging.NewJSONHandler(os.Stdout, &level)))

	if err := run(context.Background(), &level); err != nil {
		slog.Error("startup failed", "version", version, "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, level *slog.LevelVar) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	level.Set(cfg.LogLevel)

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	h, err := app.New(ctx, cfg, awsCfg)
	if err != nil {
		return err
	}

	slog.Info("starting",
		"version", version,
		"revision", revision(),
		"presignup_enabled", cfg.PreSignUp.Enabled,
		"postconfirmation_enabled", cfg.PostConfirmation.Enabled,
		"preauthentication_enabled", cfg.PreAuthentication.Enabled,
		"preauthentication_password_rotation_enabled", cfg.PreAuthentication.Enabled && cfg.PreAuthentication.PasswordRotation.Enabled,
		"email_verification_enabled", cfg.PreSignUp.Enabled && cfg.EmailVerification.Enabled,
	)
	lambda.Start(h.Handle)
	return nil
}

// revision returns the VCS revision the binary was built from, if known.
func revision() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return "unknown"
}
