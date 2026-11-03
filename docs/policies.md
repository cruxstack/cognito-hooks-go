# Policies

Each hook's decision is made by a
[Rego](https://www.openpolicyagent.org/docs/policy-language) policy that you
write. The policy receives the Cognito event as `input` and defines a
`result` rule.

| Hook                                  | Policy setting                     | Package                          | Required |
| ------------------------------------- | ---------------------------------- | -------------------------------- | -------- |
| [PreSignUp](presignup.md)             | `APP_PRESIGNUP_POLICY_PATH`        | `cognito_hook_presignup`         | yes      |
| [PostConfirmation](postconfirmation.md) | `APP_POSTCONFIRMATION_POLICY_PATH` | `cognito_hook_postconfirmation` | no       |

The hook pages describe each input and result. The
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

## Writing robust policies

- **Always define a result.** An undefined result is an error, which
  rejects a sign-up or, for PostConfirmation, scrambles the password. Use a
  `default` value, or an `else` chain that ends in an unconditional value:

  ```rego
  default result := {"action": "allow"}
  ```

- **Don't define one rule twice with different values.** Two `result` rules
  that both match with different values are an evaluation error. Chain them
  with `else`, which picks the first match:

  ```rego
  result := deny("undeliverable address") if {
  	input.emailVerification.valid == false
  } else := {"action": "allow"}
  ```

- **Decide what a missing value means.** `not
  input.emailVerification.valid` is true when verification didn't run or
  SendGrid was unavailable, which would deny every sign-up during a SendGrid
  outage. `input.emailVerification.valid == false` only matches a real
  verdict.

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

Each event prints its decision and the outcome (`allow`, `deny: <reason>`,
`scramble`, `skip: <reason>`, or the error). The command fails if any event
does. Useful flags:

| Flag                       | Effect                                                                         |
| -------------------------- | ------------------------------------------------------------------------------ |
| `-postconfirmation-policy` | The PostConfirmation policy, for `PostConfirmation_*` events.                  |
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
