# Datadog IaC Scanner

Static analysis for Infrastructure as Code. The scanner covers the platforms
listed by `list-platforms`: Ansible, CI/CD, CloudFormation, Docker Compose,
Dockerfile, Kubernetes and Terraform. It parses a repository, evaluates Rego
rules against the parsed documents and writes a SARIF report. It started as a
fork of KICS.

**This repository is public.** Never put customer names, internal links,
credentials or content from private repositories in code, fixtures, commit
messages or pull request descriptions.

## Layout

- `cmd/scanner/` is the CLI. Its commands are `scan`, `custom`,
  `list-platforms`, `list-queries`, `list-modules`, `show-config`,
  `test-rules`, `serve` and `fetch-bundle`.
- `cmd/custom-playground/` is a local editor for custom Rego rules
  (`make playground`).
- `pkg/scan/` orchestrates a scan: file discovery, query source, one service
  per parser, then post-scan.
- The scan pipeline lives in:
  - `pkg/analyzer/`: classifies each file by platform.
  - `pkg/parser/`: one parser per platform; Terraform modules live in
    `pkg/parser/terraform/modules/`.
  - `pkg/resolver/`: renders Helm charts and resolves files.
  - `pkg/engine/`: evaluates Rego; query sources are in `pkg/engine/source/`.
  - `pkg/report/`: SARIF and the other output formats.
- `pkg/config/` reads `code-security.datadog.yaml` from the root of the scanned
  repository (see `README.md`). The decoder is strict: an unknown key makes the
  file invalid.
- `pkg/datadog/` is the Datadog API client (rulesets, libraries, remote config).
- `pkg/platforms/` holds `Supported`, the platforms exposed to users and the
  default value of `scan -t`.
- `e2e/` runs end-to-end tests against the built binary (see
  `e2e/README.md`). `test/e2e/` runs end-to-end scans in-process. `test/`
  also holds the helpers and fixtures shared by the tests (see
  `test/README.md`).
- `rules_generator/`, `frameworks_sync/` and `sync_tools/` are maintenance
  scripts. Each has its own README.

## Rules are not in this repository

The scanner loads its rules at run time from one of three sources.

| Source | How to use it | Network |
|---|---|---|
| Datadog API (default) | Downloads the default ruleset and Rego libraries. With `DD_API_KEY` and `DD_APP_KEY` (or `DD_JWT_TOKEN`), it also loads the org's custom ruleset and remote configuration. | Needs `api.<DD_SITE>` (default `api.datadoghq.com`). The default ruleset needs no credentials. |
| Offline bundle | Run `fetch-bundle --output-dir <bundle>` once, then `scan --offline-bundle-path <bundle>`. | None at scan time. |
| Local rules | `scan -q <queries-dir>`: only these rules run. | Rego libraries still come from the API unless `--libraries-path` is set. |

The default ruleset can change between two runs. **To compare two engine
builds, pin the rules with an offline bundle.**

Rules (Rego, metadata, fixtures, cross-platform consistency) are written where
they are maintained, not here. After an engine change, run `test-rules`: it
runs the rule tests stored in the backend against this engine.

## Commands

Run every command from the repository root.

| What | Command | Healthy result |
|---|---|---|
| Build | `go build -o bin/datadog-iac-scanner ./cmd/scanner` | About 30 s; `bin/` is git-ignored |
| Release-style build | `make build` | Runs `go mod tidy` and `go generate` first, so `go.mod` and `go.sum` may change |
| Unit tests (as in CI) | `go test $(go list ./... \| grep -v /e2e) -count=1` | Every package prints `ok`, no `FAIL` line (about 80 s on a laptop). Both end-to-end packages are excluded. |
| In-process end-to-end tests | `go test ./test/e2e -count=1` | `ok` (about 30 s) |
| One test | `go test ./pkg/scan/ -run TestName -count=1 -v` | `--- PASS` |
| Binary end-to-end tests | `make test-e2e` builds the binary and runs the suite. With an existing build: `go test ./e2e -count=1 -run Test_E2E_Config` | `ok` (about 35 s). CI never fails this job (`\|\| cat results.json`), so read the results yourself. |
| Rule tests against this engine | `./bin/datadog-iac-scanner test-rules -t Dockerfile` (omit `-t` for all platforms) | `PASS: <n> rules` |
| Go lint | `golangci-lint run -c .golangci.yml --timeout 20m` | No issues. CI pins v2.4.0; use the same version if results differ. |
| Rego changes | `opa fmt --fail .` and `regal lint` with the flags from `.github/workflows/lint-rego.yml` | Exit code 0 |
| New dependency | Update `LICENSE-3rdparty.csv` | The CI `lint-licenses` job passes |

Run Go lint before every commit or push that touches Go code.

## Scanning locally

```bash
./bin/datadog-iac-scanner scan -p <repo-dir> -o <out-dir> [-t Terraform] [--log-level info]
```

- The scanned path must be inside a git repository that has an **`origin`
  remote and at least one commit**. Otherwise the scan fails with exit code
  126. For a scratch fixture:
  `git init && git remote add origin https://example.invalid/fixture.git && git add -A && git commit -m fixture`.
- The report is written to `<out-dir>/datadog-iac-scanner-result.sarif`.
  `--metadata-path <file>` also writes the scan statistics as JSON.
- **Exit codes:**
  - `0`: no finding.
  - `20`, `30`, `40`, `50` or `60`: success. The code gives the highest severity
    found, from INFO (20) to CRITICAL (60). It is not an error.
  - `126`: engine error, including missing git information.
  - `127`: invalid configuration.
  - `130`: interrupted.
- The default log level is `error`. Use `--log-level info` to see what the scan
  does.

## Rules of thumb and gotchas

- **The repository configuration is untrusted input.** It comes from the
  scanned repository. Features that execute code or reach the network are
  enabled by CLI flags (for example `--terraform-modules`), never by that file.
- **Worktree name.** Some unit tests find the repository root by walking up to
  a directory named exactly `datadog-iac-scanner` (`test.ChangeCurrentDir`).
  Keep that name as the last element of a worktree path, for example
  `../worktrees/<branch>/datadog-iac-scanner`. Otherwise those tests fail with
  ``could not find a `datadog-iac-scanner` subdirectory``.
- **Timing-sensitive test.** `TestGitHTTPSCloneUsesInstallationPaths` gives its
  clone 10 s and can be killed on a busy machine. Rerun it alone before you
  suspect your change.
- **`Supported` affects every default scan.** Adding a platform changes what a
  scan without `-t` parses, and so its file counts and output. Check for
  non-regression on repositories without that platform.
- **Comparing SARIF between builds.** Ignore `tool.driver.version` and the
  `DATADOG_EXECUTION_TIME_SECS` tag. Pin the rules with an offline bundle.

## Profiling

`--profiling CPU|MEM` is a global flag. It writes one pprof file per scan phase
to the system temp directory and logs its path at info level.

- `CPU` logs the CPU time of each phase.
- `MEM` logs the live heap at the end of each phase. It is a snapshot of the
  whole process, not memory that belongs to the phase.

```bash
./bin/datadog-iac-scanner --profiling CPU scan -p <path>          # or MEM
go tool pprof -base <prev-phase>.prof <cur-phase>.prof           # this phase only
go tool pprof -sample_index=alloc_space <cur-phase>.prof         # total allocations
```
