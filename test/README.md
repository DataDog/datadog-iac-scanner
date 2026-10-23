# Tests

The scanner has three levels of tests. Run every command from the repository
root.

| Level | Location | What runs | Command |
|---|---|---|---|
| Unit | `*_test.go` files next to the code | Go packages, in-process | `go test $(go list ./... \| grep -v /e2e) -count=1` |
| In-process end-to-end | `test/e2e/` | Full scans through the `scan` package | `go test ./test/e2e -count=1` (about 30 s) |
| Binary end-to-end | `e2e/` (see [its README](../e2e/README.md)) | The built `bin/datadog-iac-scanner` | `make test-e2e` |

The unit command is the one CI runs. It excludes both end-to-end packages.

## This directory

- **`helpers.go`** holds helpers shared by tests in other packages.
  `ChangeCurrentDir` finds the repository root by walking up to a directory
  named `datadog-iac-scanner`. Keep that name for your checkout or worktree,
  otherwise the tests that use it fail.
- **`fixtures/`** holds input files for unit tests across packages, such as
  `pkg/runner`, `pkg/analyzer` and `pkg/parser`.
- **`assets/`** holds sample inputs and expected results, for example for
  remediation and Kubernetes tests.
- **`e2e/`** holds the in-process end-to-end tests: inline exclusions,
  OpenTofu files, the Terraform plan flag, the offline bundle and v1.4 rule
  configs.
  - Most of them load their rules from `e2e/testdata/rules/`, but still fetch
    the Rego libraries from the Datadog API, so they need network access.
  - `Test_E2EOfflineBundle` runs without network access.
- **`modules/`** holds legacy rule fixtures. No test references them any more.

## Make targets

`make test-short`, `make test-unit`, `make test-cover`, `make test-race` and
`make test-coverage-report` all run `go mod tidy` and `go generate` first, so
they can change `go.mod` and `go.sum`. CI calls `go test` directly.

## CI

| Workflow | What it runs |
|---|---|
| `.github/workflows/go-ci.yml` | Unit tests on Linux, Windows and macOS |
| `.github/workflows/test-gate.yml` | A selected set of packages in short mode, including `./test/...` |
| `.github/workflows/go-e2e.yaml` | Binary end-to-end tests. The job does not fail on test failures. |
| `.github/workflows/test-rules.yml` | `test-rules`: the rule tests stored in the backend, run against the built engine |
