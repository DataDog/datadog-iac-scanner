---
title: "GitHub environment file injection"
group_id: "CICD / GitHub"
meta:
  name: "github/github_env"
  id: "e8f9a0b1-c2d3-44e5-f6a7-b8c9d0e1f2a3"
  display_name: "GitHub environment file injection"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `e8f9a0b1-c2d3-44e5-f6a7-b8c9d0e1f2a3`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://securitylab.github.com/research/github-actions-untrusted-input/)

### Description

Writing to the special GitHub Actions environment files GITHUB_ENV or GITHUB_PATH from workflow steps that handle untrusted input can inject environment variables or alter PATH, enabling attackers to escalate privileges or achieve arbitrary code execution. This rule inspects GitHub Actions workflow steps with a `run:` body in workflows using dangerous triggers, such as `pull_request_target` or `workflow_run`, and flags occurrences that write to those files. It detects the `>`, `>>` shell redirections, pipeline-to-tee patterns, PowerShell `Out-File`/`Add-Content`/`Set-Content`/`Tee-Object`, and Windows `cmd` echo/write patterns targeting `$GITHUB_ENV`, `$GITHUB_PATH`, `${env:GITHUB_ENV}`, `%GITHUB_ENV%`, etc. The audit ignores trivially static `echo` statements with only literal text but will flag commands that include variable expansion, command substitution, multiple arguments, or unknown commands which may introduce attacker-controlled data.

Secure alternative using step outputs instead of writing to `GITHUB_ENV`:

```yaml
steps:
  - id: set_val
    run: |
      echo "value=foo" >> $GITHUB_OUTPUT
  - name: Use value
    env:
      FOO: ${{ steps.set_val.outputs.value }}
```

## Compliant Code Examples
```yaml
name: GitHub Env Test - Negative Cases

# Safe: No dangerous triggers
on:
  push:
    branches: [main]

jobs:
  safe-trigger:
    runs-on: ubuntu-latest
    steps:
      # Even with GITHUB_ENV writes, this is safe because of the trigger
      - name: Safe with push trigger
        run: echo $foo >> $GITHUB_ENV

---
name: Safe Patterns with Dangerous Trigger
on: pull_request_target

jobs:
  safe-static-echo:
    runs-on: ubuntu-latest
    steps:
      # Safe: completely static strings
      - name: Static string literal
        run: echo "FOO=bar" >> $GITHUB_ENV

      - name: Static without quotes
        run: echo completely-static >> $GITHUB_ENV

  no-env-write:
    runs-on: ubuntu-latest
    steps:
      - name: Regular echo
        run: echo "Hello World"

      - name: Write to different file
        run: echo $foo >> $OTHER_FILE

      - name: Comment only
        run: echo $foo >> $OTHER_ENV # not $GITHUB_ENV

  wrong-variables:
    runs-on: ubuntu-latest
    steps:
      - name: Similar but not exact variable name
        run: echo $foo >> $GITHUB

      - name: Another similar name
        run: echo $foo | tee $GITHUB_ENVX

  actions-only:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 18

```
## Non-Compliant Code Examples
```yaml
name: GitHub Env Test - Positive Cases
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  bash-redirect-unsafe:
    runs-on: ubuntu-latest
    steps:
      - name: Unsafe echo with variable
        run: echo $foo >> $GITHUB_ENV

      - name: Unsafe echo with multiple variables
        run: echo $foo $bar >> $GITHUB_ENV

      - name: Unsafe echo with command substitution
        run: echo FOO=$(bar) >> $GITHUB_ENV

      - name: Unsafe with braces
        run: echo $foo >> ${GITHUB_ENV}

      - name: Unsafe with quotes
        run: echo $foo >> "$GITHUB_ENV"

  bash-pipeline:
    runs-on: ubuntu-latest
    steps:
      - name: Unsafe tee pattern
        run: something | tee $GITHUB_ENV

      - name: Unsafe tee with quotes
        run: something | tee "$GITHUB_ENV"

  bash-path:
    runs-on: ubuntu-latest
    steps:
      - name: Unsafe GITHUB_PATH write
        run: echo $foo >> $GITHUB_PATH

  powershell-unsafe:
    runs-on: windows-latest
    steps:
      - name: Out-File pattern
        shell: pwsh
        run: |
          echo "CUDA_PATH=$env:CUDA_PATH" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append

      - name: Add-Content pattern
        shell: pwsh
        run: |
          Add-Content -Path $env:GITHUB_ENV -Value "RELEASE_VERSION=$releaseVersion"

      - name: Set-Content pattern
        shell: pwsh
        run: |
          Set-Content -Path $env:GITHUB_ENV -Value "tag=$tag"

      - name: Tee-Object pattern
        shell: pwsh
        run: |
          echo "BRANCH=${{ env.BRANCH_NAME }}" | Tee-Object -Append -FilePath "${env:GITHUB_ENV}"

      - name: PowerShell redirect
        shell: pwsh
        run: |
          echo "UV_CACHE_DIR=$UV_CACHE_DIR" >> $env:GITHUB_ENV

  cmd-unsafe:
    runs-on: windows-latest
    steps:
      - name: CMD redirect pattern
        shell: cmd
        run: echo LIBRARY=%LIBRARY% >> %GITHUB_ENV%

```