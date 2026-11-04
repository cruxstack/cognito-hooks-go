# Policies

Each hook's decisions are made by a
[Rego](https://www.openpolicyagent.org/docs/policy-language) policy that you
write. The policy receives the Cognito event as `input` and defines a
`result` rule with the [actions](#actions) the hook should take.

| Hook                                  | Policy setting                     | Package                          | Required |
| ------------------------------------- | ---------------------------------- | -------------------------------- | -------- |
| [PreSignUp](presignup.md)             | `APP_PRESIGNUP_POLICY_PATH`        | `cognito_hook_presignup`         | yes      |
| [PostConfirmation](postconfirmation.md) | `APP_POSTCONFIRMATION_POLICY_PATH` | `cognito_hook_postconfirmation` | no       |
| [PreAuthentication](preauthentication.md) | `APP_PREAUTHENTICATION_POLICY_PATH` | `cognito_hook_preauthentication` | no    |

The hook pages describe each input and the actions each hook accepts. The
[`examples/policies`](../examples/policies) directory has complete, tested
policies to start from.

- Policies must use Rego v1 syntax (`if` and `contains` keywords).
  `import rego.v1` is optional.
- Policies are compiled when the function starts, so a syntax error, or a
  policy that doesn't define `result` in its package (such as a misspelled
  package name), stops the function from starting instead of failing a
  user's sign-up.
- Start the file with its `package` line. The
  [Terraform module](https://github.com/cruxstack/terraform-aws-cognito-hooks)
  checks that the policy content starts with it.

## Actions

A policy's result is a list of actions:

```jsonc
{
  "actions": [
    "signup.allow",                                   // a name
    { "action": "signup.deny", "reason": "..." }      // or an object with parameters
  ]
}
```

- **Names are `<resource>.<verb>`,** such as `signup.allow`, `user.confirm`,
  or `password.replace`, and are case-insensitive. Each hook's page lists
  the actions it accepts.
- **When actions conflict, the more restrictive one wins:** `signup.deny`
  over `signup.allow`, and `password.replace` over `password.skip`.
- **The hook decides the order** in which actions run, so the order of the
  list doesn't matter.
- **Unknown actions and parameters make the result invalid,** including
  another hook's actions and misspelled parameters. An invalid result is
  handled like a failed policy: the sign-up is rejected, or the
  PostConfirmation and PreAuthentication hooks apply their default actions.

New actions are added as new names, so a policy written today keeps working
when a hook learns more actions.

Build the list with `contains` rules. Each rule adds actions independently,
so rules can't conflict with each other:

```rego
package cognito_hook_presignup

import rego.v1

result := {"actions": actions}

actions contains "signup.allow"

actions contains {"action": "signup.deny", "reason": "Disposable addresses can't be used."} if {
	input.emailVerification.disposable == true
}

actions contains {"action": "signup.deny", "reason": "Sign-up is closed for this app."} if {
	input.callerContext.clientId == "1example23456789"
}
```

## Writing robust policies

- **Always define a result.** An undefined result is an error, which
  rejects a sign-up or, for PostConfirmation and PreAuthentication, applies
  the default actions.
  `result := {"actions": actions}` is always defined, even when no
  `actions` rule matches.

- **Define `result` once.** Two `result` rules that both match with
  different values are an evaluation error. Add to `actions` with
  `contains` rules instead.

- **Decide what a missing value means.** `not
  input.emailVerification.valid` is true when verification didn't run or
  SendGrid was unavailable, which would deny every sign-up during a SendGrid
  outage. `input.emailVerification.valid == false` only matches a real
  verdict.

- **Negate a named rule, not an expression on a value that may be
  missing.** `not email_domain in allowed_domains` doesn't match when the
  user has no email, so that sign-up isn't denied. Name the condition and
  negate it: `allowed_email if email_domain in allowed_domains`, then `not
  allowed_email`. See
  [`domains.rego`](../examples/policies/presignup/domains.rego).

- **Don't name policy rules `test_*`.** `opa test` runs every rule with that
  prefix as a test, including rules in the policy itself.

- **Keep secrets out of policies.** The policy is packaged with the function
  and can be read by anyone who can download its code.

## Testing policies

Evaluate a policy against sample events without AWS credentials or network
calls:

```sh
go run ./cmd/devtool eval \
  -presignup-policy examples/policies/presignup/domains.rego \
  -events examples/events/presignup.json
```

Each event prints the policy's actions, the resolved decision, and the
outcome, such as `signup.allow, user.confirm`, `signup.deny: <reason>`,
`password.replace`, `password.skip: <reason>`, or the error. The command
fails if any event does. Useful flags:

| Flag                       | Effect                                                                         |
| -------------------------- | ------------------------------------------------------------------------------ |
| `-postconfirmation-policy` | The PostConfirmation policy, for `PostConfirmation_*` events.                  |
| `-preauthentication-policy` | The PreAuthentication policy, for `PreAuthentication_*` events. eval reads no rotation records, so `passwordReplacedAt` is `null` and `password.replace` means the hook replaces the password if it is stale. |
| `-verdict Invalid`         | Gives PreSignUp events a SendGrid result with this verdict (`Valid`, `Risky`, `Invalid`). |
| `-verify-triggers`         | The trigger sources `-verdict` applies to; `PreSignUp_SignUp` by default.      |
| `-show-input`              | Prints the exact policy input for each event.                                  |

Events can be one event object or an array. With `APP_LOG_LEVEL=debug`, the
function logs every event it receives, so you can copy real events.

Policies can also have Rego unit tests, run with the
[OPA CLI](https://www.openpolicyagent.org/docs/cli):

```sh
opa test examples/policies/presignup/domains.rego examples/policies/presignup/domains_test.rego
```

The example policies and their tests run in CI (`make test-policies`).
