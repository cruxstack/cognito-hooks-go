# Cognito Hooks

An extensible set of AWS Lambda handlers for [Amazon Cognito triggers](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-working-with-lambda-triggers.html).
The project is hook-agnostic; **PreSignUp** is implemented first, and the same
core will be reused for additional hooks over time.

A policy layer (OPA, Rego v1) makes allow/deny decisions and can set Cognito
response flags. Optionally, policy input is enriched with SendGrid email
verification data. A local debug runner lets you exercise fixtures without
real credentials.

## Features

* **multi-hook architecture**: common types and helpers live under `internal`;
  each hook has its own handler and a small `cmd/<hook>/main.go`
* **policy-based decisions**: custom flows with OPA policies
* **optional sendgrid verification**: include verdict and score in policy
  input; trusted domains can be allowlisted to bypass checks
* **local debug mode**: run integration tests against fixture events and
  policies with zero external dependencies
* **structured logging**: json logs via `slog` with runtime level control

> **Notes**: future hooks may be added using the same pattern (e.g.,
> PostConfirmation, PreAuthentication, CustomMessage). Timelines are
> intentionally unspecified.

## Environment Variables

Configure Lambda or local runs via environment variables. See `.env.sample`
for a ready-to-copy template.

| Variable                                      | Description                                                  | Default                    |
| --------------------------------------------- | ------------------------------------------------------------ | -------------------------- |
| `APP_LOG_LEVEL`                               | log level: `debug`, `info`, `warn`, `error`                  | `info` (or `debug` if dbg) |
| `APP_DEBUG_ENABLED`                           | enable extra debug logging                                   | `false`                    |
| `APP_DEBUG_DATA_PATH`                         | path to JSON array of sample events                          | `fixtures/debug-data.json` |
| `APP_POLICY_PATH`                             | path to Rego policy (v1)                                     | **required**               |
| `APP_EMAIL_VERIFICATION_ENABLED`              | enable sendgrid verification                                 | `false`                    |
| `APP_EMAIL_VERIFICATION_FOR_TRIGGER_SOURCES`  | comma delimited string of triggers to verify                 | `PreSignUp_SignUp`         |
| `APP_EMAIL_VERIFICATION_WHITELIST`            | comma delimited string of domains to auto-allow (lowercased) | `""`                       |
| `APP_SENDGRID_API_HOST`                       | sendgrid api base url                                        | `https://api.sendgrid.com` |
| `APP_SENDGRID_EMAIL_VERIFICATION_API_KEY`     | sendgrid api key                                             | required if verification   |

> note: when `APP_DEBUG_ENABLED=true`, log level is forced to `debug`.

## OPA Policy

The handler queries: `data.cognito_hook_presignup.result`

### Input Shape

```jsonc
{
  "trigger": "PreSignUp_SignUp",
  "callerContext": {
    "clientId": "local"
  },
  "userAttributes": {
    "email": "user@example.org"
  },
  // present only if verification is enabled (or whitelisted)
  "emailVerification": {
    "score": 0.97,
    "valid": true,
    "disposable": false,
    "role": false,
    "raw": "{...sendgrid response...}"
  }
}
````

### Output Shape

```jsonc
{
  "action": "allow | deny",
  "reason": "string (only when deny)",
  "response": {
    "autoConfirmUser": true,
    "autoVerifyEmail": false,
    "autoVerifyPhone": false
  }
}
```

#### Example Policy

This policy denys on explicit invalid, otherwise allows.

```rego
package cognito_hook_presignup
import rego.v1

result := deny_result if {
  input.emailVerification != null
  input.emailVerification.valid == false
}

result := allow_result if {
  not deny_result
}

allow_result := { "action": "allow", "response": {} }

deny_result := {
  "action": "deny",
  "reason": "invalid email address"
} if {
  input.emailVerification != null
  input.emailVerification.valid == false
}
```

## Debug Mode & Local Integration Tests

Use the debug runner to process fixture events with your policy.

1. Copy `.env.sample` to `.env` and adjust values.

2. Run with defaults:

   ```bash
   make debug
   ```

3. Override paths:

   ```bash
   go run ./cmd/debug \
     -data ./fixtures/debug-data.json \
     -policy ./fixtures/debug-policy.rego
   ```

The runner logs each event’s computed response and any handler error. Fixture
events live in `fixtures/debug-data.json`.

## Build and Deploy (Lambda)

Build a Linux binary and zip it for Lambda.

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w" \
  -o dist/bootstrap ./cmd/presignup

touch dist/policy.rego # edit policy
cd dist && zip presignup.zip bootstrap
```

Create a Lambda function:

* runtime: `provided.al2023`
* architecture: `arm64` (or `x86_64` if you built that)
* handler: `bootstrap` (the binary name)
* upload `presignup.zip`
* set environment variables from the table above
* attach the user pool’s **PreSignup** trigger to this function

No special IAM permissions are required unless your VPC settings restrict
egress to SendGrid.
