# Contributing

## Setup

You need Go (the version in `go.mod`) and `make`. Nothing else: linters and
the vulnerability checker run with `go run` at pinned versions, and every
test runs offline. A [dev container](.devcontainer/devcontainer.json) is
included if you prefer one.

```sh
make help     # list targets
make check    # lint, test, and vulnerability check, as CI runs them
```

## Layout

```text
main.go             Lambda entry point
cmd/devtool/        local CLI (eval policies, run events)
internal/           the function; see docs/architecture.md
e2e/                end-to-end tests through the real wiring
examples/policies/  example policies, tested by examples/examples_test.go
examples/events/    sample Cognito events
docs/               user documentation
```

## Tests

- `make test` runs everything with the race detector.
- `make test-e2e` runs the end-to-end tests. They build the function with
  `app.New` from environment-style configuration and replace only the
  Cognito API and the SendGrid API. Prefer adding an end-to-end test for
  behavior a user would notice.
- `make test-policies` runs every example policy through its hook against
  the sample events, and runs their Rego unit tests. A new example policy
  needs expectations in `examples/examples_test.go`.

To try a change by hand, `make eval` evaluates the example policies, and
`make run` sends the sample events through the whole function with the
settings in `.env` (copy `.env.example`).

## Conventions

- Configuration is read only in `internal/config`, and dependencies are
  built only in `internal/app`. Other packages take what they need as
  arguments or small interfaces.
- Every new environment variable is validated at startup and documented in
  `docs/configuration.md`. A change to a policy input or result is
  documented on the hook's page in `docs/`.
- Logs use `slog` with snake_case keys and the request context
  (`slog.InfoContext(ctx, ...)`), and never include unmasked email
  addresses or passwords.
- Errors returned to Cognito are shown to users. Return a reason written for
  them, or a generic message, and log the details.

## Commits and releases

Pull request titles follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, ...); a check enforces it. Each merge to `main` is
tagged and released automatically: `fix:`, `chore:`, `docs:`, `test:`, and
`ci:` bump the patch version; `feat:`, `refactor:`, and other types bump the
minor version; and a breaking change, marked with `!` (`feat!:`, `fix!:`,
`refactor!:`) or a `BREAKING CHANGE:` footer, bumps the major version. A `!`
on `chore`, `docs`, `test`, or `ci` is still released as a patch, so use one
of the other types for breaking changes. Releases attach
`bootstrap_linux_arm64.zip`, `bootstrap_linux_amd64.zip`, and
`checksums.txt`.

Breaking changes to configuration or the policy contract affect the
[Terraform module](https://github.com/cruxstack/terraform-aws-cognito-hooks),
which builds this repository at a pinned tag. Release the module change
alongside, and add the change to the upgrade guide.
