package main

import (
	"context"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/cruxstack/cognito-hooks-go/internal/config"
	"github.com/cruxstack/cognito-hooks-go/internal/handlers"
	"github.com/cruxstack/cognito-hooks-go/internal/log"
)

func main() {
	cfg, err := config.New()
	if err != nil {
		log.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}
	log.SetLevel(cfg.AppLogLevel)

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Error("failed to load aws configuration", "error", err)
		os.Exit(1)
	}

	h, err := handlers.NewPostConfirmationHandler(cfg, cognitoidentityprovider.NewFromConfig(awsCfg))
	if err != nil {
		log.Error("failed to init handler", "error", err)
		os.Exit(1)
	}

	lambda.Start(h.Handle)
}
