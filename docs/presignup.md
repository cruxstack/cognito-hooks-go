# PreSignUp hook

Cognito invokes the
[PreSignUp trigger](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-sign-up.html)
before it creates a user. The hook runs your policy, which allows or denies
the sign-up and can set Cognito's auto-confirm and auto-verify flags.
Optionally, the hook first checks the user's email address with SendGrid and
gives the policy the result.

Enable it with `APP_PRESIGNUP_ENABLED=true` and a policy at
`APP_PRESIGNUP_POLICY_PATH`.

## Triggers

| Trigger source               | Sent when                                                   |
| ---------------------------- | ----------------------------------------------------------- |
| `PreSignUp_SignUp`           | A user signs up with `SignUp`.                              |
| `PreSignUp_AdminCreateUser`  | An administrator creates a user with `AdminCreateUser`.     |
| `PreSignUp_ExternalProvider` | A user signs in through a federated identity provider for the first time. |

## How it works

1. If email verification is on for the trigger and the user has an `email`
   attribute, the address is verified (see [below](#email-verification)).
2. The policy evaluates the event and returns `allow` or `deny`.
3. On `allow`, the hook returns the policy's flags to Cognito. On `deny`, it
   returns the policy's reason as an error, and Cognito rejects the sign-up.

## Policy input

```jsonc
{
  "trigger": "PreSignUp_SignUp",
  "userPoolId": "us-east-1_EXAMPLE",
  "region": "us-east-1",
  "userName": "8a1b2c3d-0000-4000-8000-000000000001",
  "callerContext": {
    "awsSdkVersion": "aws-sdk-unknown-unknown",
    "clientId": "1example23456789"
  },
  "userAttributes": { "email": "emma@example.com" },
  // the ValidationData the app passed to SignUp; {} when there is none
  "validationData": {},
  // the ClientMetadata the app passed to SignUp; {} when there is none
  "clientMetadata": { "locale": "en" },

  // set when verification ran and the address could be checked
  "emailVerification": {
    "provider": "sendgrid", // sendgrid or allowlist
    "valid": true,          // false only when the address is undeliverable
    "verdict": "Risky",     // Valid, Risky, or Invalid
    "score": 0.5,           // 0 to 1
    "disposable": true,     // a disposable email service's domain
    "role": false,          // a role address such as admin@ or support@
    "raw": "{...}"          // SendGrid's raw response as a JSON string
  }
}
```

## Policy result

The policy is read from `APP_PRESIGNUP_POLICY_PATH` and must define
`data.cognito_hook_presignup.result`.

To allow the sign-up:

```jsonc
{
  "action": "allow",
  // optional; every flag defaults to false
  "response": {
    "autoConfirmUser": true,  // confirm the user without a code
    "autoVerifyEmail": false, // mark the email address verified
    "autoVerifyPhone": false  // mark the phone number verified
  }
}
```

What Cognito does with the flags:

- It ignores them for `PreSignUp_AdminCreateUser`.
- It rejects the sign-up if a flag asks it to verify an attribute the user
  doesn't have, such as `autoVerifyEmail` without an `email` attribute.
- Auto-verifying skips the proof that the user owns the address or phone
  number. When `email` (or `phone_number`) is a sign-in alias and another
  user already has it, Cognito moves the alias to the new user and marks the
  other user's address unverified. Only auto-verify what something else has
  proved, and don't decide on `callerContext.clientId` alone: an app client
  ID isn't a secret unless the client has a client secret.

To deny it:

```json
{ "action": "deny", "reason": "Sign-up is limited to example.com addresses." }
```

The reason is shown to the user. Cognito returns `PreSignUp failed with
error <reason>.` to the app, so write it for the user, and leave out
anything you wouldn't show them. Without a reason the user sees `sign-up is
not allowed`.

## Failure handling

The hook fails closed: when it can't make a decision, the sign-up is
rejected.

| Situation                                                     | Result                                              |
| ------------------------------------------------------------- | --------------------------------------------------- |
| The policy allows the sign-up                                 | the policy's flags are returned                     |
| The policy denies the sign-up                                 | rejected with the policy's reason                   |
| The policy fails, has no result, or returns an unknown action | rejected with `the sign-up policy failed`; logged   |
| SendGrid is unavailable or returns an error                   | logged; the policy runs without `emailVerification` |
| The policy doesn't compile or define its `result` rule        | the function doesn't start                          |

A denial is returned to Cognito as an error, so the function's `Errors`
metric counts every denied sign-up. To alarm on failures rather than
denials, use CloudWatch Logs metric filters on the function's log group for
`{ $.msg = "sign-up rejected because the policy failed" }` and
`{ $.msg = "startup failed" }`.

## Email verification

With `APP_EMAIL_VERIFICATION_ENABLED=true`, the hook checks the user's
address with the
[SendGrid Email Address Validation API](https://www.twilio.com/docs/sendgrid/ui/managing-contacts/email-address-validation)
(it needs a SendGrid Email API Pro or Premier plan) before the policy runs:

- Only sign-ups whose trigger source is in
  `APP_EMAIL_VERIFICATION_FOR_TRIGGER_SOURCES` are verified;
  `PreSignUp_SignUp` by default. Administrators and identity providers
  usually vouch for their users' addresses.
- Addresses in a domain in `APP_EMAIL_VERIFICATION_ALLOWLIST` are treated as
  valid without calling SendGrid (`provider` is `allowlist`, `score` is 1).
  Domains match exactly; list subdomains separately.
- Each check has a 3 second timeout, because Cognito waits at most 5 seconds
  for the trigger. A timeout or an error from SendGrid is logged and the
  policy runs without `emailVerification`.

Verification only reports. The policy decides what to do with the result;
[`verification.rego`](../examples/policies/presignup/verification.rego)
denies undeliverable and disposable addresses, and lets sign-ups through
when SendGrid is unavailable.

## Examples

| Policy                                                                         | Shows                                                         |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------- |
| [`allow.rego`](../examples/policies/presignup/allow.rego)                      | Allowing every sign-up: the smallest valid policy.            |
| [`domains.rego`](../examples/policies/presignup/domains.rego)                  | Limiting self sign-up to some email domains.                  |
| [`auto-confirm.rego`](../examples/policies/presignup/auto-confirm.rego)        | Auto-confirming a test app client's sign-ups, and the risks.  |
| [`verification.rego`](../examples/policies/presignup/verification.rego)        | Denying undeliverable and disposable addresses.               |

See [policies](policies.md) for writing and testing policies.
