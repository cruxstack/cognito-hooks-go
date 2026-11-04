# PreAuthentication hook

Cognito invokes the
[pre authentication trigger](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-authentication.html)
when a user starts to sign in. This hook evaluates an optional policy and
carries out the features it has enabled. It has one feature today,
[password rotation](#password-rotation), which is off by default. With no
feature enabled, the hook makes no AWS calls and lets every sign-in
continue unchanged.

Enable the hook with `APP_PREAUTHENTICATION_ENABLED=true`. Once the function
is attached as the user pool's pre authentication trigger, features can be
turned on and off with settings on the function, without changing the user
pool.

| Feature                                 | Setting                                           | Default |
| --------------------------------------- | ------------------------------------------------- | ------- |
| [Password rotation](#password-rotation) | `APP_PREAUTHENTICATION_PASSWORD_ROTATION_ENABLED` | `false` |

## When it runs

| Trigger source                     | Sent when                                                                    |
| ---------------------------------- | ---------------------------------------------------------------------------- |
| `PreAuthentication_Authentication` | A user starts to sign in with `InitiateAuth` or `AdminInitiateAuth`, or on managed login's sign-in page. Federated users' later sign-ins send it too. |

The hook can only act when Cognito runs the trigger:

- **Refreshing tokens doesn't run it.** The hook acts when a user signs in,
  not on sessions that already exist.
- **Unknown usernames run it only when the app client sets
  `PreventUserExistenceErrors` to `ENABLED`,** with `userNotFound` set to
  `true`.

## Policy

Set `APP_PREAUTHENTICATION_POLICY_PATH` to choose the actions per user. The
policy must define `data.cognito_hook_preauthentication.result` as
`{"actions": [...]}` (see [actions](policies.md#actions)). Each action
belongs to a feature and only has an effect when that feature is enabled:

| Action             | Feature           | Effect                                                                   | Parameters          |
| ------------------ | ----------------- | ------------------------------------------------------------------------ | ------------------- |
| `password.replace` | password rotation | Replaces the password if it is stale. The default when the policy returns no `password.*` action, and wins over `password.skip`. |   |
| `password.skip`    | password rotation | Keeps the password.                                                      | `reason` (optional; logged) |

The policy runs for every event, including unknown, federated, and
unconfirmed users, so actions added later can apply to them too.

Input:

```jsonc
{
  "trigger": "PreAuthentication_Authentication",
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
  "validationData": {},
  "userNotFound": false,
  "passwordReplacedAt": "2026-11-02T14:03:51.123456789Z"
}
```

- `validationData` holds the `ClientMetadata` of the `InitiateAuth` or
  `AdminInitiateAuth` request.
- `passwordReplacedAt` is when the hooks last replaced the password. It is
  `null` when password rotation is disabled, when the hooks never replaced
  the password, when the record couldn't be read, and for unknown,
  federated, and unconfirmed users, whose record the hook doesn't read.

Result:

```jsonc
{ "actions": [{ "action": "password.skip", "reason": "end-to-end test user" }] }
```

A policy that fails, has no result, or returns an unknown action or
parameter is logged, and the hook applies each feature's default actions. A
policy that doesn't compile or define its `result` rule stops the function
from starting, so every sign-in fails.

[`skip-users.rego`](../examples/policies/preauthentication/skip-users.rego)
keeps the passwords of a list of users, by `sub` or username.

> [!CAUTION]
> Don't skip users by app client ID (`callerContext.clientId`) or by
> `validationData`. An app client without a secret has a public ID, which
> ships in your web or mobile app, and the app chooses its own
> `ClientMetadata`. Anyone could sign in through that client, or with that
> metadata, and keep a leaked password working.

## Password rotation

Enable it with `APP_PREAUTHENTICATION_PASSWORD_ROTATION_ENABLED=true`, and
set the [cutoff](#the-cutoff) and the [rotation table](#rotation-records).
The hook then replaces the password of each native, confirmed user whose
password the hooks haven't replaced since the cutoff. The new password is
random, has 128 characters, and is never logged or returned. A password set
before the cutoff, such as one exposed in a credential-stuffing attack,
stops working, while users who sign in with passwordless factors, such as
email one-time passwords, notice nothing.

Each user's password is replaced once, at their first sign-in after the
cutoff. Replacing every password in bulk would cost more: each
`AdminSetUserPassword` call makes the user a billable monthly active user,
and a user who signs in is already one that month.

> [!IMPORTANT]
> Enable password rotation only in a user pool whose app clients allow a
> passwordless first factor (choice-based sign-in with `EMAIL_OTP`,
> `SMS_OTP`, or `WEB_AUTHN`). Otherwise users can't sign in once their
> password is replaced.

> [!WARNING]
> **Unverified: whether the new password applies to the sign-in that
> triggered the replacement.** Cognito might read the stored password before
> it invokes the trigger. If it does, a leaked password works one last time
> and fails from the next attempt on. Nobody has tested this yet; see
> [how to test it](#does-the-new-password-apply-to-the-same-sign-in) in a
> test user pool before you rely on either outcome.

Turning password rotation off doesn't depend on its other settings: with
`APP_PREAUTHENTICATION_PASSWORD_ROTATION_ENABLED=false`, the cutoff and the
table are ignored, and the hook stops calling Cognito and DynamoDB.

### Requirements

- The function's execution role needs `cognito-idp:AdminSetUserPassword`
  and `cognito-idp:AdminGetUser` on the user pool, and `dynamodb:GetItem`
  and `dynamodb:PutItem` on the rotation table. See
  [IAM permissions](configuration.md#iam-permissions).
- A DynamoDB table whose partition key is `sub`, a string. See
  [rotation records](#rotation-records).
- Nothing in the password policy needs to change: the password has 128
  characters (a policy's minimum length is at most 99) and always includes
  lowercase and uppercase letters, digits, and symbols.

### Which passwords it replaces

It never replaces the password of these users, whatever the policy returns:

| User                                       | Why                                                                          |
| ------------------------------------------ | ---------------------------------------------------------------------------- |
| Unknown (`userNotFound` is `true`)         | There is no user.                                                            |
| Federated (`cognito:user_status` of `EXTERNAL_PROVIDER`) | A password would turn the federated profile into a password login. |
| Unconfirmed (`UNCONFIRMED`)                | A permanent password would confirm the user without verifying their email address. |

Users with any other status, such as `FORCE_CHANGE_PASSWORD` or
`RESET_REQUIRED`, have a password that someone may know, so it is replaced.
Because the new password is permanent, Cognito sets their status to
`CONFIRMED`.

If your PostConfirmation policy keeps the passwords of end-to-end test users,
list the same users in this hook's policy too, or their passwords are
replaced at their first sign-in.

### How it works

1. The hook reads the user's `sub` and `cognito:user_status` from the
   event's user attributes. If either is missing, it looks the user up with
   `AdminGetUser` rather than guess.
2. Unless the user is one of those above, it reads the user's
   [rotation record](#rotation-records).
3. If there is a policy, it returns the actions for the user. Without one,
   the default is `password.replace`.
4. Unless the user is one of those above or the policy returned
   `password.skip`, the hook replaces a stale password: one the hooks never
   replaced, or replaced before the cutoff. It calls `AdminSetUserPassword`
   with `Permanent: true` and a random password from `crypto/rand`, then
   records the time.
5. It returns the event unchanged.

Two sign-ins of the same user at the same time may both replace the
password. That is harmless, so the hook doesn't lock.

### The cutoff

`APP_PREAUTHENTICATION_ROTATE_BEFORE` is an RFC 3339 timestamp, such as
`2026-11-01T00:00:00Z`. A password the hooks haven't replaced since then is
replaced at the user's next sign-in.

- **Use a time that has passed,** such as when the passwords were exposed.
  A cutoff in the future stops the function from starting: until it passed,
  every replacement would be before it, so every sign-in would replace the
  password again.
- **Moving it later** gives every user a new password once more, at their
  next sign-in.
- **The record is of the hooks' replacements,** not of every password
  change. A password a user chooses later, for example with
  `ConfirmForgotPassword`, is kept if the hooks replaced theirs after the
  cutoff, and replaced at their next sign-in otherwise. The
  [PostConfirmation hook](postconfirmation.md) replaces those passwords
  when they are chosen.

### Rotation records

Cognito doesn't record when a password was set: `AdminGetUser` returns only
`UserCreateDate` and `UserLastModifiedDate`, and the second changes with any
attribute update. So the hook keeps its own record, in the DynamoDB table
named by `APP_PREAUTHENTICATION_ROTATION_TABLE`:

| Attribute     | Type                | Value                                                    |
| ------------- | ------------------- | -------------------------------------------------------- |
| `sub`         | S (partition key)   | The user's `sub`.                                        |
| `replaced_at` | S                   | When the hooks last replaced the password, RFC 3339 in UTC. |

The record isn't a Cognito custom attribute, for two reasons: writing user
attributes uses the user pool's `UserUpdate` quota (25 requests per second,
shared with other attribute updates), and an app client allowed to write the
attribute would let an attacker's session mark its password as already
replaced.

Set `APP_POSTCONFIRMATION_ROTATION_TABLE` to the same table on the
PostConfirmation hook, and it records its replacements too, so a newly
confirmed user doesn't get another new password at their first sign-in.

### Failure handling

Password rotation fails closed: when it can't tell whether a password may
be kept, or can't replace it, the hook rejects the sign-in rather than let
Cognito check an old password. Cognito shows the user `PreAuthentication
failed with error Sign-in is temporarily unavailable. Try again in a
moment.`, and the hook logs the details.

| Situation                                                     | Result                                             |
| ------------------------------------------------------------- | -------------------------------------------------- |
| Unknown, federated, or unconfirmed user                       | password kept; logged as `password replacement skipped` |
| The policy returns `password.skip`                            | password kept; logged with the policy's reason     |
| The hooks replaced the password since the cutoff              | password kept; logged as `password already replaced` |
| The policy fails, has no result, or returns an unknown action or parameter | default actions, so a stale password is replaced; the policy error is logged |
| `sub` or `cognito:user_status` is missing and `AdminGetUser` fails | sign-in rejected; logged as `user lookup failed` |
| Reading the rotation record fails or times out                | password treated as stale and replaced; logged     |
| `AdminSetUserPassword` fails, is throttled, or times out      | sign-in rejected; logged as `password replacement failed` |
| Writing the record fails after a replacement                  | sign-in continues; logged as `password replacement not recorded`. The next sign-in replaces the password again. |
| A setting is invalid, or the policy doesn't compile or define its `result` rule | the function doesn't start, so every sign-in fails |

### Time limits

Cognito waits at most 5 seconds for the function, including a cold start.
The hook gives the user lookup, the record read, and the replacement 3
seconds together, with at most 1 second for the read so a slow table leaves
time to replace the password, and then 0.5 seconds to record the
replacement. The AWS SDK retries each call at most once, after at most
200 milliseconds.

### Quotas

`AdminSetUserPassword` shares a quota of 30 requests per second, which can't
be raised, with `ForgotPassword`, `ChangePassword`, and the PostConfirmation
hook. Each user's password is replaced only once, so the load is highest
right after the cutoff, when nobody has a record yet. When sign-ins come
faster than the quota allows, some replacements are throttled and those
sign-ins are rejected; the user can try again a moment later.

There is no setting that lets throttled sign-ins through: an attacker could
cause the throttling on purpose, for example with `ForgotPassword`
requests, to use it. Turning password rotation off stops the replacements
altogether.

### Monitoring

- **The function's `Errors` metric** counts rejected sign-ins: failed
  replacements and lookups, events the function can't decode, and every
  sign-in while the function can't start (an invalid setting or policy logs
  `startup failed`).
- **CloudWatch Logs metric filters** on the function's log group tell the
  causes apart:

  ```text
  { $.msg = "password replacement failed" }
  { $.msg = "user lookup failed" }
  { $.msg = "password replacement not recorded" }
  { $.msg = "rotation record unavailable, treating the password as stale" }
  ```

  Throttled replacements log a `TooManyRequestsException` error.

## Unverified behavior

### Does the new password apply to the same sign-in?

This hasn't been verified. With `USER_SRP_AUTH`, `InitiateAuth` returns
values derived from the stored password verifier (`SALT`, `SRP_B`, and
`SECRET_BLOCK`), and Cognito might read that verifier before it invokes the
trigger. The same question applies to `USER_PASSWORD_AUTH`, and to
`USER_AUTH` with the `PASSWORD` and `PASSWORD_SRP` challenges. If the new
password doesn't apply to the sign-in that triggered the replacement, the
old password works one last time and the next attempt fails.

To find out, use a test user pool, never a production one:

1. Allow the `PASSWORD` and `EMAIL_OTP` first factors in the user pool, and
   create an app client without a secret that allows `ALLOW_USER_AUTH`,
   `ALLOW_USER_SRP_AUTH`, and `ALLOW_USER_PASSWORD_AUTH`.
2. Deploy the hook with password rotation enabled, a cutoff that has
   passed, and `APP_LOG_LEVEL=debug`, and attach it as the user pool's pre
   authentication trigger. Don't list the test user in the policy.
3. Create a confirmed test user with a verified email address, and note its
   `sub`.
4. For each flow (`USER_PASSWORD_AUTH`, `USER_SRP_AUTH`, and `USER_AUTH`
   with the `PASSWORD` and `PASSWORD_SRP` challenges):

   1. Set a known password and delete the user's rotation record:

      ```sh
      aws cognito-idp admin-set-user-password --user-pool-id "$POOL_ID" \
        --username "$USERNAME" --password "$PASSWORD" --permanent
      aws dynamodb delete-item --table-name "$TABLE" \
        --key '{"sub": {"S": "'"$SUB"'"}}'
      ```

   2. Sign in with the known password. For `USER_PASSWORD_AUTH`:

      ```sh
      aws cognito-idp initiate-auth --client-id "$CLIENT_ID" \
        --auth-flow USER_PASSWORD_AUTH \
        --auth-parameters USERNAME="$USERNAME",PASSWORD="$PASSWORD"
      ```

      The SRP flows need a client that computes the SRP values, such as an
      AWS SDK helper or AWS Amplify's `signIn`. For `USER_AUTH`, ask for the
      challenge with `PREFERRED_CHALLENGE`.
   3. Check that the function logged `password replaced` for this attempt,
      and note which API call ran the trigger. Then note whether the
      attempt returned tokens or failed with `NotAuthorizedException`.
   4. Sign in again with the same password. It must fail; if it doesn't,
      the password wasn't replaced.
   5. Sign in with `USER_AUTH` and `PREFERRED_CHALLENGE=EMAIL_OTP`, and
      check that it still works.

If the first attempt fails, the new password applied to it, and a leaked
password stops working at once. If the first attempt returns tokens and the
second fails, the old password worked one last time. Record the result for
each flow on this page.

### Does the event include `sub` and `cognito:user_status`?

AWS documents the trigger's `userAttributes` without listing them, and the
events haven't been checked. Password rotation doesn't depend on it: when
either attribute is missing, the hook looks the user up with
`AdminGetUser`, which adds a Cognito API call to each such sign-in. The
debug log in the test above shows the events Cognito sends.
