# Upgrading to v1

v1 restructures the function and tightens its contracts. Policies written
for v0 usually keep working; configuration needs a few changes. If you
deploy with the
[Terraform module](https://github.com/cruxstack/terraform-aws-cognito-hooks),
upgrade it to v2, which runs v1 of this function, instead of setting these
variables yourself.

Upgrade checklist:

1. Build or download v1 and update the configuration below.
2. Check your policies against the [policy changes](#policy-changes) and run
   them through `devtool eval` with a few sample events.
3. Pin the version you build. Building from a branch picks up breaking
   changes without warning.

## Building

- **One binary for every hook.** Build `bootstrap` from the repository root
  (`go build -tags lambda.norpc -o bootstrap .`) or download
  `bootstrap_linux_arm64.zip` or `bootstrap_linux_amd64.zip` from the
  release. `cmd/presignup` and `cmd/debug` were removed.
- **Go 1.27.3 or later** is required to build.

## Configuration

Each function now enables the hooks it handles. v1 refuses to start when a
removed variable is set to a non-empty value, and names the replacement in
the error.

| v0                                   | v1                                                                        |
| ------------------------------------ | ------------------------------------------------------------------------- |
| `APP_POLICY_PATH`                    | `APP_PRESIGNUP_ENABLED=true` and `APP_PRESIGNUP_POLICY_PATH`              |
| `APP_DEBUG_ENABLED`                  | removed: use `APP_LOG_LEVEL=debug`, and `devtool` locally                 |
| `APP_DEBUG_DATA_PATH`                | removed: use `devtool run -events`                                        |
| `APP_EMAIL_VERIFICATION_WHITELIST`   | `APP_EMAIL_VERIFICATION_ALLOWLIST`                                        |

`APP_LOG_LEVEL`, `APP_EMAIL_VERIFICATION_ENABLED`,
`APP_EMAIL_VERIFICATION_FOR_TRIGGER_SOURCES`, `APP_SENDGRID_API_HOST`, and
`APP_SENDGRID_EMAIL_VERIFICATION_API_KEY` are unchanged.

Other changes:

- **Invalid values are errors.** v0 treated any boolean other than `true` as
  `false` (so `TRUE` disabled verification) and any unknown log level as
  `info`. v1 refuses to start.
- **`APP_SENDGRID_EMAIL_VERIFICATION_API_KEY` is required** when
  verification is enabled. v0 sent requests without a key, and SendGrid's
  error was reported to the policy as a valid address.
- **`APP_EMAIL_VERIFICATION_FOR_TRIGGER_SOURCES`** must list PreSignUp
  trigger sources.

## Policy changes

The PreSignUp policy's package (`cognito_hook_presignup`), its `result`
rule, and the result shape are unchanged.

- **A failed PreSignUp policy rejects the sign-up.** v0 allowed the sign-up
  when the policy failed to evaluate or had no result. v1 rejects it with
  `the sign-up policy failed` and logs the error.
- **Actions are validated.** PreSignUp actions must be `allow` or `deny`
  (any case). v0 allowed every action other than `deny`, including typos
  such as `Deny`.
- **`emailVerification` is missing when verification didn't run:** when
  it's disabled, the trigger isn't listed, the user has no email, or
  SendGrid failed. v0 passed a perfect result (`valid: true`, `score: 100`)
  when verification was disabled or the trigger wasn't listed. A policy that
  requires `input.emailVerification.valid` denies those sign-ups in v1;
  compare with `== false` instead.
- **SendGrid errors no longer look like valid addresses.** v0 reported an
  error response (such as an invalid API key) as a valid address with a
  score of 0. v1 leaves out `emailVerification`.
- **`emailVerification.score` is always 0 to 1.** v0 reported `100` for
  allowlisted domains. Policies that compare the score to `100` need
  updating.
- **`emailVerification` has new fields:** `provider` (`sendgrid` or
  `allowlist`) and `verdict`. `disposable` and `role` are now set from
  SendGrid's checks; v0 always reported `false`.
- **New input fields:** `userPoolId`, `region`, `userName`, and, for
  PreSignUp, `validationData`. `userAttributes`, `validationData`, and
  `clientMetadata` are `{}`, not `null`, when the event has none.
- **A denial without a reason** shows the user `sign-up is not allowed`
  instead of an empty message.

## Behavior changes

- **Events for a hook that isn't enabled are errors.** A function only
  handles the hooks enabled in its configuration.
- **Policies are compiled once at startup.** v0 compiled the PreSignUp
  policy for every event. A policy with a syntax error, or one that doesn't
  define `result` in its package (for example a misspelled package name),
  now stops the function from starting.
- **`APP_SENDGRID_API_HOST` must be an `https` URL.** The API key is sent
  with every request.
- **SendGrid requests time out after 3 seconds,** so a slow response can't
  use up Cognito's 5 second limit. v0 had no timeout.
- **The SendGrid request body is JSON-encoded.** v0 inserted the address
  into the request unescaped, so an address with a `"` could change which
  address SendGrid validated.
- **Logs carry `request_id`, `trigger`, `user_pool_id`, and `client_id`,**
  and email addresses are masked.

## New in v1

- **The PostConfirmation hook,** which scrambles each newly confirmed native
  user's password for passwordless-only user pools. See
  [PostConfirmation](postconfirmation.md).
- **`devtool eval`** evaluates policies against sample events offline, and
  **`devtool run`** runs events through the whole function.
- **Prebuilt release binaries** for `linux/arm64` and `linux/amd64`.
