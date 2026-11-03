# PostConfirmation hook

Cognito invokes the
[PostConfirmation trigger](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-post-confirmation.html)
after a user confirms their sign-up or resets a forgotten password. This hook
replaces the user's password with a random 128-character password that is
never logged or returned. Nobody, including the user, knows it, so the user
can only sign in with passwordless factors, such as email or SMS one-time
passwords and passkeys. Stolen or guessed passwords stop working, and
because the user now has a password, `ChangePassword` requires a previous
password they don't know.

Enable it with `APP_POSTCONFIRMATION_ENABLED=true`. A policy is optional.

> [!IMPORTANT]
> Use the hook only with a user pool whose app clients allow a passwordless
> first factor (choice-based sign-in with `EMAIL_OTP`, `SMS_OTP`, or
> `WEB_AUTHN`). Otherwise users can't sign in after they confirm.

## Requirements

- The function's execution role needs `cognito-idp:AdminSetUserPassword` on
  the user pool. See [IAM permissions](configuration.md#iam-permissions).
- Nothing in the password policy needs to change: the password has 128
  characters (a policy's minimum length is at most 99) and always includes
  lowercase and uppercase letters, digits, and symbols.

## When it runs

| Trigger source                           | Sent after                                                         |
| ---------------------------------------- | ------------------------------------------------------------------ |
| `PostConfirmation_ConfirmSignUp`         | `ConfirmSignUp` or `AdminConfirmSignUp`, or a sign-up confirmed in managed login. |
| `PostConfirmation_ConfirmForgotPassword` | `ConfirmForgotPassword`, so the password the user just chose is replaced too. |

The hook only sees the users Cognito sends it, so some users keep a password
they know:

- **Users created with `AdminCreateUser`.** Cognito doesn't invoke the
  trigger for them, so they keep the password they choose at their first
  sign-in.
- **Users that a PreSignUp trigger auto-confirms** (`autoConfirmUser`), and
  **federated users.** AWS doesn't document whether the trigger runs for
  them; check in a test user pool if you rely on it. The hook skips users
  whose `cognito:user_status` is `EXTERNAL_PROVIDER`, because they have no
  Cognito password.

If no user may sign in with a password, also leave `PASSWORD` out of the
user pool's allowed first factors. The hook is then defense in depth for
the users above and for app clients that still allow password flows.

## How it works

1. Federated users (`cognito:user_status` of `EXTERNAL_PROVIDER`) are
   skipped.
2. If there is a policy, it can skip the user. Without one, every native
   user's password is scrambled.
3. The hook calls `AdminSetUserPassword` with `Permanent: true` and a random
   password from `crypto/rand` that always includes lowercase, uppercase,
   digit, and symbol characters.

## Policy

Set `APP_POSTCONFIRMATION_POLICY_PATH` to exempt users, for example the app
client of an end-to-end test suite that signs in with a password. The policy
must define `data.cognito_hook_postconfirmation.result`.

Input:

```jsonc
{
  "trigger": "PostConfirmation_ConfirmSignUp",
  "userPoolId": "us-east-1_EXAMPLE",
  "region": "us-east-1",
  "userName": "8a1b2c3d-0000-4000-8000-000000000001",
  "callerContext": {
    "awsSdkVersion": "aws-sdk-unknown-unknown",
    "clientId": "1example23456789"
  },
  "userAttributes": {
    "sub": "8a1b2c3d-0000-4000-8000-000000000001",
    "email": "emma@example.com",
    "email_verified": "true",
    "cognito:user_status": "CONFIRMED"
  },
  "clientMetadata": {}
}
```

Result:

```jsonc
{
  "action": "scramble", // or "skip"
  "reason": "end-to-end test client" // optional; logged when skipped
}
```

[`skip-clients.rego`](../examples/policies/postconfirmation/skip-clients.rego)
skips a list of app clients.

## Failure handling

The hook never fails the confirmation. Cognito has already confirmed the
user, so an error would only show the user a failure without undoing
anything. When the hook can't make a decision, it scrambles the password.

| Situation                                                     | Result                                             |
| ------------------------------------------------------------- | -------------------------------------------------- |
| Federated user                                                | skipped; logged                                    |
| The policy skips the user                                     | skipped; logged with the policy's reason           |
| The policy fails, has no result, or returns an unknown action | scrambled; the policy error is logged              |
| `AdminSetUserPassword` fails                                  | logged as `password scramble failed`; success      |
| The policy doesn't compile or define its `result` rule        | the function doesn't start                         |

## Monitoring

Each of these leaves a confirmed user with the password they chose, so
alarm on both:

- **The function's `Errors` metric.** The function returns an error, and
  Cognito still confirms the user, when it can't start (an invalid setting
  or policy logs `startup failed`), when the PostConfirmation hook isn't
  enabled on it, or when the event can't be decoded.
- **Failed scrambles,** which return success. Use a CloudWatch Logs metric
  filter on the function's log group:

  ```text
  { $.msg = "password scramble failed" }
  ```
