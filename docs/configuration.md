# Configuration

The function is configured with environment variables. They are validated
when the function starts: an unknown value, a missing required value, or a
variable removed in v1 stops the function from starting, and the error lists
every problem at once.

Booleans are `true` or `false`. Lists are comma-separated.

## Hooks

One binary serves every hook. Enable the hooks a function should handle; an
event for a hook that isn't enabled is an error.

| Variable                           | Description                                                                          | Default               |
| ---------------------------------- | ------------------------------------------------------------------------------------ | --------------------- |
| `APP_PRESIGNUP_ENABLED`            | Handle `PreSignUp_*` events. See [PreSignUp](presignup.md).                          | `false`               |
| `APP_PRESIGNUP_POLICY_PATH`        | Path to the PreSignUp policy, relative to the working directory (`/var/task` in Lambda). | required when enabled |
| `APP_POSTCONFIRMATION_ENABLED`     | Handle `PostConfirmation_*` events. See [PostConfirmation](postconfirmation.md).     | `false`               |
| `APP_POSTCONFIRMATION_POLICY_PATH` | Path to the PostConfirmation policy. Without one, every native user's password is replaced. | unset         |
| `APP_POSTCONFIRMATION_ROTATION_TABLE` | DynamoDB table to record each replacement in, so the PreAuthentication hook doesn't replace the password again. | unset |
| `APP_PREAUTHENTICATION_ENABLED`    | Handle `PreAuthentication_*` events. See [PreAuthentication](preauthentication.md).  | `false`               |
| `APP_PREAUTHENTICATION_POLICY_PATH` | Path to the PreAuthentication policy. | unset |
| `APP_PREAUTHENTICATION_PASSWORD_ROTATION_ENABLED` | Turn on the PreAuthentication hook's [password rotation](preauthentication.md#password-rotation). | `false` |
| `APP_PREAUTHENTICATION_ROTATE_BEFORE` | Password rotation's [cutoff](preauthentication.md#the-cutoff), an RFC 3339 timestamp that has passed, such as `2026-11-01T00:00:00Z`. Passwords the hooks haven't replaced since then are replaced at the next sign-in. | required with password rotation |
| `APP_PREAUTHENTICATION_ROTATION_TABLE` | Password rotation's DynamoDB table of [rotation records](preauthentication.md#rotation-records), with the partition key `sub` (string). | required with password rotation |
| `APP_LOG_LEVEL`                    | `debug`, `info`, `warn`, or `error`. `debug` logs every event, including user attributes. | `info`           |

At least one hook must be enabled.

## Email verification

Used by the PreSignUp hook, and only checked when it is enabled. See
[email verification](presignup.md#email-verification).

| Variable                                     | Description                                                                 | Default                    |
| -------------------------------------------- | --------------------------------------------------------------------------- | -------------------------- |
| `APP_EMAIL_VERIFICATION_ENABLED`             | Verify the user's address with SendGrid before the policy runs.             | `false`                    |
| `APP_EMAIL_VERIFICATION_FOR_TRIGGER_SOURCES` | PreSignUp trigger sources to verify for.                                    | `PreSignUp_SignUp`         |
| `APP_EMAIL_VERIFICATION_ALLOWLIST`           | Domains treated as valid without calling SendGrid (exact, case-insensitive match). | unset               |
| `APP_SENDGRID_API_HOST`                      | SendGrid API host, an `https` URL. EU accounts use `https://api.eu.sendgrid.com`. | `https://api.sendgrid.com` |
| `APP_SENDGRID_EMAIL_VERIFICATION_API_KEY`    | API key with Email Address Validation access.                               | required when enabled      |

Lambda environment variables are visible to anyone who can read the
function's configuration. Restrict `lambda:GetFunctionConfiguration`, or
encrypt the variables with a KMS key.

## Packaging

The function reads its policies from files in the deployment package. By
convention they are named after their hook:

```text
lambda.zip
├── bootstrap
├── presignup.rego          # APP_PRESIGNUP_POLICY_PATH=presignup.rego
├── postconfirmation.rego   # APP_POSTCONFIRMATION_POLICY_PATH=postconfirmation.rego
└── preauthentication.rego  # APP_PREAUTHENTICATION_POLICY_PATH=preauthentication.rego
```

`make package PRESIGNUP_POLICY=... POSTCONFIRMATION_POLICY=...
PREAUTHENTICATION_POLICY=...` builds this zip. The same zip can back one
function per hook (each with its own hook enabled), or one function attached
to several triggers.

## IAM permissions

The execution role needs the
[`AWSLambdaBasicExecutionRole`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSLambdaBasicExecutionRole.html)
permissions to write logs and, when the PostConfirmation hook is enabled:

```json
{
  "Effect": "Allow",
  "Action": "cognito-idp:AdminSetUserPassword",
  "Resource": "arn:aws:cognito-idp:us-east-1:111122223333:userpool/us-east-1_EXAMPLE"
}
```

When the PreAuthentication hook's password rotation is enabled, it also
looks users up, and reads and writes the rotation table. Without password
rotation, the PreAuthentication hook needs no AWS permissions.
PostConfirmation needs only `PutItem` on the table, and only with
`APP_POSTCONFIRMATION_ROTATION_TABLE`:

```json
[
  {
    "Effect": "Allow",
    "Action": ["cognito-idp:AdminSetUserPassword", "cognito-idp:AdminGetUser"],
    "Resource": "arn:aws:cognito-idp:us-east-1:111122223333:userpool/us-east-1_EXAMPLE"
  },
  {
    "Effect": "Allow",
    "Action": ["dynamodb:GetItem", "dynamodb:PutItem"],
    "Resource": "arn:aws:dynamodb:us-east-1:111122223333:table/cognito-hooks-password-rotations"
  }
]
```

The PreSignUp hook needs no AWS permissions. With email verification, it
needs outbound HTTPS access to the SendGrid API.

Cognito needs permission to invoke the function: a resource-based policy
statement for the principal `cognito-idp.amazonaws.com`, with the user
pool's ARN as the source ARN.

## Lambda settings

- **Runtime:** `provided.al2023`, handler `bootstrap`, `arm64` or `x86_64`.
- **Timeout:** 5 seconds. Cognito waits at most 5 seconds for a trigger, so
  a longer timeout doesn't help.
- **Triggers:** attach the function as the user pool's `PreSignUp`,
  `PostConfirmation`, and/or `PreAuthentication` trigger, matching the hooks
  it has enabled.
- **Logs:** JSON on stdout. Every record for an event carries `request_id`,
  `trigger`, `user_pool_id`, and `client_id`. PreSignUp records add the
  user's masked `email` (`e***@example.com`), and PostConfirmation and
  PreAuthentication records add the user's `sub`.
- **AWS SDK retries:** each Cognito and DynamoDB call is retried at most
  once, so retries fit in Cognito's 5 seconds.
- **Alarms:** see monitoring for [PreSignUp](presignup.md#failure-handling),
  [PostConfirmation](postconfirmation.md#monitoring), and
  [PreAuthentication](preauthentication.md#monitoring). A PreSignUp denial
  is a function error, so the hooks need different alarms.
