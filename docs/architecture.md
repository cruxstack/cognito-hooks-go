# Architecture

One Lambda function serves every hook. Cognito invokes it synchronously with
a trigger event and waits up to 5 seconds for the response; the function
routes the event to the hook for its trigger source, which returns the
(possibly changed) event or an error.

```text
Cognito ─▶ handler ─┬─▶ PreSignUp:        verify ─▶ policy ─▶ actions ─▶ allow (flags) / deny (error)
           (routes  │                     (SendGrid) (Rego)
           by trigger)
                    └─▶ PostConfirmation: policy ─▶ actions ─▶ AdminSetUserPassword
                                          (Rego)               (Cognito; not for federated users)
```

Each policy returns a list of [actions](policies.md#actions), such as
`signup.allow` or `password.skip`. The hook resolves them (the more
restrictive action wins) and carries them out in its own order.

## Packages

| Package                     | Responsibility                                                                                       |
| --------------------------- | ---------------------------------------------------------------------------------------------------- |
| `main.go`                   | Lambda entry point: logging, configuration, `app.New`, `lambda.Start`.                               |
| `cmd/devtool`               | Local CLI: `eval` policies against events, `run` events through the whole function.                  |
| `internal/app`              | Composition root. Builds every dependency from the configuration; options replace the Cognito and HTTP clients in tests and the devtool. |
| `internal/config`           | Reads and validates environment variables. No other package reads the environment.                  |
| `internal/handler`          | Decodes the event, adds log context, and routes it by trigger source to a hook.                      |
| `internal/presignup`        | The PreSignUp hook: policy input, resolving its actions, and email verification.                     |
| `internal/postconfirmation` | The PostConfirmation hook: the optional policy, its actions, and the password replacement.          |
| `internal/cognito`          | The policy input fields every hook shares.                                                           |
| `internal/policy`           | Compiles and evaluates Rego policies.                                                                |
| `internal/action`           | Decodes the actions a policy returns (`{"actions": [...]}`), which each hook resolves.               |
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
  error couldn't undo anything. A failed or invalid policy falls back to
  the default actions, which replace the password, and a failed replacement
  is logged.
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

## Adding an action

1. Add the action's name (`<resource>.<verb>`) to the hook's action
   constants and `Actions` list, and resolve it in the hook's `Decide`: decode
   its parameters with `Action.Decode`, and decide how it combines with the
   other actions (the more restrictive one wins).
2. Carry it out in the hook's `Handle`, in a fixed order, and log the result.
3. Add it to the hook's page in `docs/`, with an example policy and tests.

A new action is a minor release: existing policies don't return it.

## Adding a hook

1. Add `internal/<hook>` with the hook's trigger prefix, policy query,
   `PolicyInput` (embedding `cognito.Header`), its actions and `Decide`, and
   a `Hook` with `Handle(ctx, *Event) error`.
2. Add a field to `handler.Handler` and a case to its router.
3. Add `APP_<HOOK>_ENABLED` (and `_POLICY_PATH`) to `internal/config`, and
   wire the hook in `internal/app`.
4. Add sample events, an example policy, an end-to-end test, a `devtool
   eval` case, and a `docs/<hook>.md` page.
