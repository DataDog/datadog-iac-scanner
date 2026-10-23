# Binary end-to-end tests

These tests run the scanner binary from `bin/`, the way a user would. They check
its exit code, its output and the files it generates.

## Run

```bash
make test-e2e                                   # builds bin/datadog-iac-scanner, then runs the suite
go test ./e2e -count=1 -timeout 1500s           # same, with an existing build
go test ./e2e -count=1 -run Test_E2E_Config     # one group
```

- **Skips.** Without a binary in `bin/`, every test is skipped. `-short` skips
  them too.
- **Network.** The scans fetch their rules from the Datadog API, so the tests
  need network access.
- **CI.** `.github/workflows/go-e2e.yaml` builds the binary and runs this
  suite, but the job ignores test failures (`|| cat results.json`). Check the
  results yourself.

## Layout

- **`cli_test.go`** runs every case registered in `testcases/`, in parallel.
- **`config_test.go`** checks the exit codes for configuration errors:
  - an invalid local configuration exits with `127`;
  - an unreachable Datadog backend exits with `126`.
- **`testcases/`** has one file per case (`e2e-cli-NNN_<name>.go`). Each file's
  `init()` appends a `TestCase` to `testcases.Tests`.
- **`fixtures/`** holds the inputs (`samples/`), the expected files (for
  example `E2E_CLI_005_PAYLOAD.json`) and the JSON schemas (`schemas/`).
- **`utils/`** runs the binary and compares outputs.

## Writing a test case

```go
// E2E-CLI-005 - scan with --payload-path writes the payload of the scanned files.
func init() { //nolint
	Tests = append(Tests, TestCase{
		Name: "should create a payload file [E2E-CLI-005]",
		Args: args{
			Args: []cmdArgs{
				[]string{"scan", "-p", "/path/e2e/fixtures/samples/terraform.tf",
					"--payload-path", "/path/e2e/output/E2E_CLI_005_PAYLOAD.json"},
			},
			ExpectedPayload: []string{"E2E_CLI_005_PAYLOAD.json"},
		},
		WantStatus: []int{50},
	})
}
```

- **Commands.** `Args` holds one or more command lines. Every command line
  needs an entry in `WantStatus`. It also gets one in each `Expected*` field
  you use.
- **Paths.** A path starting with `/path/e2e/` is rewritten to the `e2e/`
  directory. Any other `/path/<dir>/` prefix is rewritten to the repository
  root (see `utils.DevPathAdapter`).
- **Generated files.** Write them under `/path/e2e/output/` and put the case ID
  in their name. Cases run in parallel, and `output/` is deleted after the run.
- **Checks.** Only the exit code is required.
  - `WantStatus` is the exit code of each command. `0` means no finding;
    `20` to `60` give the highest severity found, from INFO to CRITICAL.
  - `Validation` is a function that receives the whole output, joined with `;`.
  - `ExpectedOutputFunc` is a function per command that receives its output,
    joined with newlines.
  - `ExpectedPayload` compares `output/<file>` with `fixtures/<file>`.
  - `ExpectedResult` takes one `ResultsValidation` per command, for example
    `{ResultsFile: "datadog-iac-scanner-result", ResultsFormats: []string{"sarif"}}`
    (see `testcases/e2e-cli-030_output-path.go`).
    - When `fixtures/<ResultsFile>.json` exists, the runner compares
      `output/<ResultsFile>.json` with it.
    - The runner validates `output/<ResultsFile>.sarif` against
      `fixtures/schemas/result-sarif.json` **only if** `ResultsFormats`
      contains `"sarif"`. Without it, the SARIF is not checked.
  - `ExpectedLog` is a `LogValidation{LogFile: "<log file>", ValidationFunc: ...}`.
    The function receives the content of `output/<log file>`. The check runs
    only when `ValidationFunc` is set.
