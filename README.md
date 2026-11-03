# Cognito Hooks

An AWS Lambda function for
[Amazon Cognito user pool triggers](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-working-with-lambda-triggers.html).
[Rego](https://www.openpolicyagent.org/docs/policy-language) policies you
write make each hook's decisions, so you can change who may sign up without
changing code.

The easiest way to deploy it is the
[terraform-aws-cognito-hooks](https://github.com/cruxstack/terraform-aws-cognito-hooks)
module.

## Hooks

| Hook                                       | What it does                                                                                       |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| [PreSignUp](docs/presignup.md)             | Allows or denies each sign-up and sets Cognito's auto-confirm and auto-verify flags. Can check the address with SendGrid first. |
| [PostConfirmation](docs/postconfirmation.md) | Replaces the password of each user who confirms their sign-up or resets their password with a random one, for passwordless-only user pools. |

One binary serves every hook; each function enables the hooks it handles.

## Features

- **Policy-driven decisions.** Allow, deny, or auto-confirm by email domain,
  app client, trigger, user attribute, or client metadata.
- **Email verification** with the SendGrid Email Address Validation API:
  deny undeliverable and disposable addresses, with an allowlist of trusted
  domains.
- **Passwordless enforcement.** Scramble passwords on confirmation and after
  password resets, so only passwordless factors can sign in.
- **Safe by default.** Configuration and policies are checked at startup, a
  broken PreSignUp policy rejects sign-ups instead of letting them through,
  and logs mask email addresses.

## How it works

Cognito calls the function with a trigger event. The function routes it to
the hook for its trigger source, and the hook evaluates your policy:

```rego
package cognito_hook_presignup

import rego.v1

default result := {"action": "deny", "reason": "Sign-up is limited to example.com addresses."}

result := {"action": "allow"} if endswith(input.userAttributes.email, "@example.com")
```

A denial's reason is shown to the user. See [policies](docs/policies.md) for
writing and testing policies, and [`examples/policies`](examples/policies)
for tested examples.

## Deploying

### With Terraform

```hcl
module "cognito_hooks" {
  source  = "cruxstack/cognito-hooks/aws"
  version = "~> 2.0" # module v2 runs v1 of this function

  presignup_hook_enabled        = true
  presignup_hook_policy_content = file("${path.module}/presignup.rego")
}
```

### By hand

1. Download `bootstrap_linux_arm64.zip` (or `amd64`) from the
   [latest release](https://github.com/cruxstack/cognito-hooks-go/releases/latest),
   or build it with `make build`.
2. Add your policy to the zip: `zip bootstrap_linux_arm64.zip presignup.rego`.
   (`make package PRESIGNUP_POLICY=presignup.rego` builds and zips in one
   step.)
3. Create a Lambda function with the `provided.al2023` runtime, the matching
   architecture, handler `bootstrap`, and a 5 second timeout. For
   PostConfirmation, give its role the
   [IAM permission](docs/configuration.md#iam-permissions).
4. Set the [environment variables](docs/configuration.md):

   ```sh
   APP_PRESIGNUP_ENABLED=true
   APP_PRESIGNUP_POLICY_PATH=presignup.rego
   ```

5. Allow `cognito-idp.amazonaws.com` to invoke the function, and set it as
   the user pool's `PreSignUp` (or `PostConfirmation`) trigger.

## Local development

Evaluate a policy against sample events, with no AWS access:

```sh
go run ./cmd/devtool eval \
  -presignup-policy examples/policies/presignup/domains.rego \
  -events examples/events/presignup.json
```

Run events through the whole function, with your `.env`. Passwords aren't
changed unless you pass `-live`:

```sh
cp .env.example .env
make run
```

`make help` lists the other targets; [CONTRIBUTING](CONTRIBUTING.md) covers
tests and conventions.

## Documentation

| Document                                       | Covers                                                      |
| ---------------------------------------------- | ----------------------------------------------------------- |
| [PreSignUp](docs/presignup.md)                 | The PreSignUp hook, its policy, and email verification.     |
| [PostConfirmation](docs/postconfirmation.md)   | The PostConfirmation hook, its requirements, and its policy. |
| [Policies](docs/policies.md)                   | Writing and testing policies.                               |
| [Configuration](docs/configuration.md)         | Environment variables, packaging, IAM, Lambda settings.     |
| [Architecture](docs/architecture.md)           | Packages, the request flow, failure handling, new hooks.    |
| [Upgrading to v1](docs/upgrading-to-v1.md)     | Breaking changes from v0.                                   |

## License

[MIT](LICENSE)
