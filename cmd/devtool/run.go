package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"

	"github.com/cruxstack/cognito-hooks-go/internal/app"
	"github.com/cruxstack/cognito-hooks-go/internal/config"
	"github.com/cruxstack/cognito-hooks-go/internal/presignup"
)

// runResult is printed for each event.
type runResult struct {
	Index   int    `json:"index"`
	Trigger string `json:"trigger"`
	// Response is the event the function returns to Cognito.
	Response any `json:"response,omitempty"`
	// Denied is the reason a PreSignUp policy denied the sign-up.
	Denied string `json:"denied,omitempty"`
	Error  string `json:"error,omitempty"`
}

func runCmd(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	eventsPath := fs.String("events", "", "JSON file with an event or an array of events (required)")
	envFile := fs.String("env", ".env", "dotenv file to load; variables already set take precedence")
	live := fs.Bool("live", false, "call Cognito AdminSetUserPassword for real, which changes the users' passwords")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *eventsPath == "" {
		fs.Usage()
		return errors.New("-events is required")
	}

	if err := loadDotEnv(*envFile); err != nil {
		return err
	}
	cfg, err := config.Load(func(key string) (string, bool) {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			return v, true
		}
		if key == "APP_LOG_LEVEL" {
			return "debug", true
		}
		return "", false
	})
	if err != nil {
		return err
	}
	slog.SetDefault(newLogger(os.Stderr, cfg.LogLevel))

	var opts []app.Option
	var awsCfg aws.Config
	if *live {
		if awsCfg, err = awsconfig.LoadDefaultConfig(ctx); err != nil {
			return err
		}
	} else {
		opts = append(opts, app.WithCognitoClient(dryRunCognito{}))
	}

	h, err := app.New(ctx, cfg, awsCfg, opts...)
	if err != nil {
		return err
	}

	events, err := readEvents(*eventsPath)
	if err != nil {
		return err
	}

	enc := newEncoder(out)
	failed := 0
	for i, raw := range events {
		res := runResult{Index: i}
		var hdr header
		_ = json.Unmarshal(raw, &hdr)
		res.Trigger = hdr.TriggerSource

		resp, err := h.Handle(ctx, raw)
		var denied *presignup.DeniedError
		switch {
		case errors.As(err, &denied):
			res.Denied = denied.Reason
		case err != nil:
			res.Error = err.Error()
			failed++
		default:
			res.Response = resp
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

// dryRunCognito logs password changes instead of making them.
type dryRunCognito struct{}

func (dryRunCognito) AdminSetUserPassword(ctx context.Context, in *cip.AdminSetUserPasswordInput, _ ...func(*cip.Options)) (*cip.AdminSetUserPasswordOutput, error) {
	slog.InfoContext(ctx, "dry run: AdminSetUserPassword not called",
		"username", aws.ToString(in.Username),
		"permanent", in.Permanent,
	)
	return &cip.AdminSetUserPasswordOutput{}, nil
}
