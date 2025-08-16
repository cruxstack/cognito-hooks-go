package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"

	"github.com/aws/aws-lambda-go/events"
	"github.com/cruxstack/cognito-hooks-go/internal/config"
	"github.com/cruxstack/cognito-hooks-go/internal/handlers"
	"github.com/cruxstack/cognito-hooks-go/internal/log"
	"github.com/joho/godotenv"
)

var (
	dataPath   string
	policyPath string
)

func init() {
	flag.StringVar(&dataPath, "data", "", "path to JSON file with test event data")
	flag.StringVar(&policyPath, "policy", "", "path to OPA policy")
	flag.Parse()
}

func NewDebugConfig() (*config.Config, error) {
	envpath := filepath.Join(".env")
	if _, err := os.Stat(envpath); err == nil {
		_ = godotenv.Load(envpath)
	}

	cfg, err := config.New()
	if err != nil {
		return nil, err
	}

	if cfg.DebugDataPath == "" {
		cfg.DebugDataPath = filepath.Join("fixtures", "debug-data.json")
	}
	if dataPath != "" {
		cfg.DebugDataPath = dataPath
	}

	if cfg.AppPolicyPath == "" {
		cfg.AppPolicyPath = filepath.Join("fixtures", "debug-policy.rego")
	}
	if policyPath != "" {
		cfg.AppPolicyPath = policyPath
	}

	return cfg, nil
}

func main() {
	cfg, err := NewDebugConfig()
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

	data, err := os.ReadFile(cfg.DebugDataPath)
	if err != nil {
		log.Error("failed to read data file", "path", cfg.DebugDataPath, "error", err)
		os.Exit(1)
	}

	evts := []events.CognitoEventUserPoolsPreSignup{}
	if err := json.Unmarshal(data, &evts); err != nil {
		log.Error("failed to parse event file", "error", err)
		os.Exit(1)
	}

	for i, e := range evts {
		rErr := ""
		r, err := h.Handle(context.Background(), e)
		if err != nil {
			rErr = err.Error()
			log.Error("integration test failed", "error", err)
		}
		rJSON, err := json.Marshal(r.Response)
		if err != nil {
			log.Error("failed to parse response", "error", err)
		}
		log.Info("event handled", "index", i, "error", rErr, "response", string(rJSON))
	}

	log.Info("integration test completed")
}
