package config

import (
	"os"
	"strings"
)

type Config struct {
	AppLogLevel                        string
	AppPolicyPath                      string
	DebugEnabled                       bool
	DebugDataPath                      string
	EmailVerificationEnabled           bool
	EmailVerificationForTriggerSources *[]string
	EmailVerificationWhitelist         *[]string
	SendGridApiHost                    string
	SendGridEmailVerificationApiKey    string
}

func New() (*Config, error) {
	cfg := &Config{
		AppLogLevel:                     os.Getenv("APP_LOG_LEVEL"),
		AppPolicyPath:                   os.Getenv("APP_POLICY_PATH"),
		DebugEnabled:                    os.Getenv("APP_DEBUG_ENABLED") == "true",
		DebugDataPath:                   os.Getenv("APP_DEBUG_DATA_PATH"),
		EmailVerificationEnabled:        os.Getenv("APP_EMAIL_VERIFICATION_ENABLED") == "true",
		SendGridApiHost:                 os.Getenv("APP_SENDGRID_API_HOST"),
		SendGridEmailVerificationApiKey: os.Getenv("APP_SENDGRID_EMAIL_VERIFICATION_API_KEY"),
	}

	evWhitelistStr := strings.TrimSpace(os.Getenv("APP_EMAIL_VERIFICATION_WHITELIST"))
	if evWhitelistStr != "" {
		evWhitelist := strings.Split(evWhitelistStr, ",")
		for i, x := range evWhitelist {
			evWhitelist[i] = strings.ToLower(strings.TrimSpace(x))
		}
		cfg.EmailVerificationWhitelist = &evWhitelist
	}

	evTriggerSourcesStr := strings.TrimSpace(os.Getenv("APP_EMAIL_VERIFICATION_FOR_TRIGGER_SOURCES"))
	if evTriggerSourcesStr == "" {
		evTriggerSourcesStr = "PreSignUp_SignUp"
	}
	evTriggerSources := strings.Split(evTriggerSourcesStr, ",")
	for i, x := range evTriggerSources {
		evTriggerSources[i] = strings.TrimSpace(x)
	}
	cfg.EmailVerificationForTriggerSources = &evTriggerSources

	if cfg.SendGridApiHost == "" {
		cfg.SendGridApiHost = "https://api.sendgrid.com"
	}

	if cfg.DebugEnabled {
		cfg.AppLogLevel = "debug"
	}

	return cfg, nil
}
