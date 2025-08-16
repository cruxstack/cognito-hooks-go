package main

import (
	"os"

	"github.com/aws/aws-lambda-go/lambda"
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

	h, err := handlers.NewPreSignupHandler(cfg)
	if err != nil {
		log.Error("failed to init handler", "error", err)
		os.Exit(1)
	}

	lambda.Start(h.Handle)
}
