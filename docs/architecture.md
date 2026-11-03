# Architecture

One Lambda function serves every hook. Cognito invokes it synchronously with
a trigger event and waits up to 5 seconds for the response; the function
routes the event to the hook for its trigger source, which returns the
(possibly changed) event or an error.

```text
Cognito ─▶ handler ─┬─▶ PreSignUp:        verify ─▶ policy ─▶ allow (flags) / deny (error)
           (routes  │                     (SendGrid) (Rego)
           by trigger)
                    └─▶ PostConfirmation: federated? ─▶ policy ─▶ AdminSetUserPassword
                                                       (Rego)     (Cognito)
```

## Packages

| Package                     | Responsibility                                                                                       |
| --------------------------- | ---------------------------------------------------------------------------------------------------- |
| `main.go`                   | Lambda entry point: logging, configuration, `app.New`, `lambda.Start`.                               |
| `cmd/devtool`               | Local CLI: `eval` policies against events, `run` events through the whole function.                  |
| `internal/app`              | Composition root. Builds every dependency from the configuration; options replace the Cognito and HTTP clients in tests and the devtool. |
| `internal/config`           | Reads and validates environment variables. No other package reads the environment.                  |
| `internal/handler`          | Decodes the event, adds log context, and routes it by trigger source to a hook.                      |
| `internal/presignup`        | The PreSignUp hook: policy input, decision validation, and email verification.                       |
| `internal/postconfirmation` | The PostConfirmation hook: the federated-user check, the optional policy, and the password scramble. |
| `internal/cognito`          | The policy input fields every hook shares.                                                           |
| `internal/policy`           | Compiles and evaluates Rego policies.                                                                |
| `internal/verify`           | Email verification with SendGrid and the domain allowlist.                                           |
| `internal/sendgrid`         | A minimal client for the SendGrid Email Address Validation API.                                      |
| `internal/password`         | Random passwords that satisfy any Cognito password policy.                                           |
| `internal/logging`          | The JSON log handler with per-event context, and email masking.                                      |

Dependencies point one way: `app` knows every package, and the hooks depend
on small interfaces (`verify.Verifier`, `postconfirmation.CognitoAPI`)
rather than on configuration or AWS clients, which keeps them testable with
fakes.

## Failure handling

Cognito triggers are synchronous: an error from the function reaches the
app that made the request. Each hook decides what an error means for it.

- **PreSignUp fails closed.** A failed or invalid policy rejects the
  sign-up, so a broken policy can't let unwanted users in. A SendGrid outage
  is not a policy failure: the policy runs without the verification result.
- **PostConfirmation never fails.** The user is already confirmed, so an
  error couldn't undo anything. A failed or invalid policy scrambles the
  password anyway, and a failed scramble is logged.
- **Misrouted events are errors.** An event for a hook that isn't enabled,
  or for an unsupported trigger, returns an error instead of passing
  through, so a function attached to the wrong trigger is noticed.

The hook pages have the full tables: [PreSignUp](presignup.md#failure-handling)
and [PostConfirmation](postconfirmation.md#failure-handling).

## Design notes

- **Configuration fails fast.** Invalid values and removed variables stop
  the function at startup, where a deployment check notices, instead of
  changing behavior on a user's sign-up.
- **Policies are compiled once,** at startup, and evaluated per event. A
  policy must define the rule its hook queries, so a misspelled package or
  rule name fails at startup rather than on every event.
- **Error messages are for users.** Cognito shows a PreSignUp error message
  to the user, so the hook returns the policy's reason or a generic message,
  and logs the details.
- **Personal data stays out of logs** unless `APP_LOG_LEVEL=debug`: email
  addresses are masked, and passwords are never logged.

## Adding a hook

1. Add `internal/<hook>` with the hook's trigger prefix, policy query,
   `PolicyInput` (embedding `cognito.Header`), `Decision`, and a `Hook` with
   `Handle(ctx, *Event) error`.
2. Add a field to `handler.Handler` and a case to its router.
3. Add `APP_<HOOK>_ENABLED` (and `_POLICY_PATH`) to `internal/config`, and
   wire the hook in `internal/app`.
4. Add sample events, an example policy, an end-to-end test, a `devtool
   eval` case, and a `docs/<hook>.md` page.
