# PostConfirmation hook

Cognito invokes the
[PostConfirmation trigger](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-post-confirmation.html)
after a user confirms their sign-up or resets a forgotten password. This hook
carries out the actions of an optional policy. Its default action,
`password.replace`, replaces the user's password with a random
128-character password that is never logged or returned. Nobody, including the user, knows it, so the user
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
- **Users that a PreSignUp trigger auto-confirms** (`user.confirm`), and
  **federated users.** AWS doesn't document whether the trigger runs for
  them; check in a test user pool if you rely on it. The hook never replaces
  the password of a user whose `cognito:user_status` is `EXTERNAL_PROVIDER`,
  because they have no Cognito password.

If no user may sign in with a password, also leave `PASSWORD` out of the
user pool's allowed first factors. The hook is then defense in depth for
the users above and for app clients that still allow password flows.

## How it works

1. If there is a policy, it returns the actions for the user. Without one,
   the default is `password.replace`.
2. Unless the user is federated (`cognito:user_status` of
   `EXTERNAL_PROVIDER`) or the policy returned `password.skip`, the hook
   calls `AdminSetUserPassword` with `Permanent: true` and a random password
   from `crypto/rand` that always includes lowercase, uppercase, digit, and
   symbol characters.
3. With `APP_POSTCONFIRMATION_ROTATION_TABLE`, it records the replacement in
   the [PreAuthentication hook's password rotation table](preauthentication.md#rotation-records),
   so that hook doesn't replace the password again at the user's first
   sign-in. This needs `dynamodb:PutItem` on the table.

## Policy

Set `APP_POSTCONFIRMATION_POLICY_PATH` to choose the actions per user, for
example to keep the passwords of an end-to-end test suite that signs in with
a password. The policy must define `data.cognito_hook_postconfirmation.result`
as `{"actions": [...]}` (see [actions](policies.md#actions)):

| Action             | Effect                                                                   | Parameters          |
| ------------------ | ------------------------------------------------------------------------ | ------------------- |
| `password.replace` | Replaces the password. The default when the policy returns no `password.*` action, and wins over `password.skip`. |   |
| `password.skip`    | Keeps the password.                                                      | `reason` (optional; logged) |

The policy runs for every user, including federated users, so actions added
later can apply to them too.

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
{ "actions": [{ "action": "password.skip", "reason": "end-to-end test client" }] }
```

[`skip-clients.rego`](../examples/policies/postconfirmation/skip-clients.rego)
keeps the passwords of a list of app clients.

## Failure handling

The hook never fails the confirmation. Cognito has already confirmed the
user, so an error would only show the user a failure without undoing
anything. When the hook can't make a decision, it applies the default
actions, so the password is replaced.

| Situation                                                     | Result                                             |
| ------------------------------------------------------------- | -------------------------------------------------- |
| Federated user                                                | password kept; logged                              |
| The policy returns `password.skip`                            | password kept; logged with the policy's reason     |
| The policy fails, has no result, or returns an unknown action or parameter | default actions; the policy error is logged |
| `AdminSetUserPassword` fails                                  | logged as `password replacement failed`; success   |
| Recording the replacement fails                               | logged as `password replacement not recorded`; success. The PreAuthentication hook replaces the password again at the next sign-in. |
| The policy doesn't compile or define its `result` rule        | the function doesn't start                         |

## Monitoring

Each of these leaves a confirmed user with the password they chose, so
alarm on both:

- **The function's `Errors` metric.** The function returns an error, and
  Cognito still confirms the user, when it can't start (an invalid setting
  or policy logs `startup failed`), when the PostConfirmation hook isn't
  enabled on it, or when the event can't be decoded.
- **Failed replacements,** which return success. Use a CloudWatch Logs
  metric filter on the function's log group:

  ```text
  { $.msg = "password replacement failed" }
  ```
