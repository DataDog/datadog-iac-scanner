# Datadog IaC Scanner — Development Guidelines

## Project Structure

- `assets/queries/<platform>/<provider>/<rule_name>/` — Detection rules (Rego)
- `assets/queries/<platform>/<provider>/<rule_name>/test/` — Test fixtures per rule
- `assets/libraries/` — Shared Rego libraries (`common.rego`, `terraform.rego`, etc.)
- `cmd/scanner/` — CLI entry point
- `test/` — Go test harness for all rules

Platforms: `terraform`, `cloudFormation`, `ansible`, `k8s`, `dockerfile`, `pulumi`, `openAPI`, and others.

## Cross-Platform Rule Consistency

**When fixing or extending a detection rule, always check for equivalent rules on other platforms.**

1. Search for the rule name pattern across all platforms:
    ```
    grep -r "<rule_name_keyword>" assets/queries/*/
    ```
2. Check if the same gap exists on each platform (e.g., a Terraform fix for `aws_security_group` may also apply to CloudFormation's `AWS::EC2::SecurityGroup`).
3. If equivalents exist, verify they cover the same resource types and edge cases. Fix them in the same PR.
4. If no equivalent exists on another platform but should, note it to user in order to add support

## Running Tests

```bash
# Test a specific rule
go test ./test -run "TestQueries.*/<rule_name>" -v -count=1

# Build and scan a directory
make build
./bin/datadog-iac-scanner scan -p <path> -o <output-dir> -t Terraform
```

## Profiling

`--profiling` is a global flag (`CPU` or `MEM`). It profiles each major scan phase and writes a pprof file per phase to the system temp dir for `go tool pprof`. For `CPU` it logs the total CPU time per phase. For `MEM` it logs the live heap (`inuse_space`) at the moment each phase ends — a whole-process snapshot, so the numbers form a footprint high-water progression across the run rather than memory attributable to a phase alone.

```bash
./bin/datadog-iac-scanner --profiling CPU scan -p <path>   # or MEM
```

To isolate a single phase's contribution, diff its pprof file against the previous phase's (the file paths are printed at info level):

```bash
go tool pprof -base <prev-phase>.prof <cur-phase>.prof   # phase-only delta
go tool pprof -sample_index=alloc_space <cur-phase>.prof # total allocations (churn)
```

## Go lint (before commit or push)

Any time you change Go code under `pkg/`, `cmd/`, or elsewhere in this module, **run golangci-lint locally before you commit or push**, using the same flags as the PR `lint` job (`.github/workflows/go-ci.yml`), so CI does not fail only after opening the PR.

```bash
golangci-lint run -c .golangci.yml --timeout 20m
```

CI pins **golangci-lint v2.4.0**; if your installed binary is a different major/minor and results disagree, align your version with CI or run the same release via the `golangci/golangci-lint:v2.4.0` image.

## Writing Rules

- Each rule needs: `query.rego`, `metadata.json`, and test fixtures (`positive*.tf`, `negative*.tf`, `positive_expected_result.json`)
- Set `resourceType` in results to match the actual resource being matched, not a hardcoded string
- Before adding a resource type to a rule, check whether an existing rule already covers it to avoid duplicate findings
