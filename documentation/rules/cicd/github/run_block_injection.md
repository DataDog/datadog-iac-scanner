---
title: "Run block injection"
group_id: "CICD / GitHub"
meta:
  name: "github/run_block_injection"
  id: "20f14e1a-a899-4e79-9f09-b6a84cd4649b"
  display_name: "Run block injection"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}20f14e1a-a899-4e79-9f09-b6a84cd4649b{{< /copyable-code >}}

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://securitylab.github.com/research/github-actions-untrusted-input/)

### Description

Run steps in GitHub Actions must not interpolate or execute GitHub event fields that can be controlled by external users, because untrusted event data such as PR/issue/discussion titles and bodies, comments, branch names, and commit metadata can contain shell metacharacters or crafted payloads that lead to command injection, arbitrary code execution on runners, or misuse of repository secrets. This risk is amplified for privileged triggers such as `pull_request_target` and some `workflow_run` scenarios. For the `pull_request` trigger, these vulnerable fields are much more significant when the change comes from a fork. Inspect the `run` property for direct references to GitHub context attributes such as `github.event.pull_request.*`, `github.event.issue.*`, `github.event.comment.*`, `github.event.discussion.*`, `github.event.workflow_run.*`, `github.head_ref`, and `github.*.authors.*`. Flag any step where the `run` string contains these patterns. To remediate, avoid shell-interpolating untrusted event data; instead, validate or sanitize inputs, use repository secrets or explicitly whitelisted values, or pass data through actions that perform strict parsing and validation before executing commands. This rule also flags `env.` usage within the `run` block. 

Secure example that avoids using untrusted event fields:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Safe run
        run: echo "Build triggered for repository ${{ github.repository }}" 
```

## Compliant Code Examples
```yaml
name: Safe composite action without inputs
description: A composite action whose run block does not interpolate untrusted data
runs:
  using: composite
  steps:
    - name: Show repository
      shell: bash
      run: |
        echo "Build triggered for ${{ github.repository }}"

```

```yaml
name: check-go-coverage

on:
  pull_request_target:
    branches: [master]

jobs:
  coverage:
    name: Check Go coverage
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Source
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Set up Go 1.22.x
        uses: actions/setup-go@v5
        with:
          go-version: 1.22.x
      - name: Run test metrics script
        id: testcov
        run: |
          make test-coverage-report | tee test-results
          echo "coverage=$(cat test-results | grep "Total coverage: " test-results | cut -d ":" -f 2 | bc)" >> $GITHUB_ENV
      - name: Checks if Go coverage is at least 80%
        if: env.coverage < 80
        run: |
          echo "Go coverage is lower than 80%: ${{ coverage }}%"
          exit 1

```

```yaml
name: Safe composite action
description: A composite action that uses inputs through environment variables to avoid shell injection
inputs:
  slack-message:
    description: The message to send
    required: true
runs:
  using: composite
  steps:
    - name: Send message safely
      shell: bash
      env:
        SLACK_MESSAGE: ${{ inputs.slack-message }}
      run: |
        echo "$SLACK_MESSAGE"

```
## Non-Compliant Code Examples
```yaml
name: Pull Request Workflow

on:
  pull_request_target:
    types:
      - opened

jobs:
  process_pull_request:
    runs-on: ubuntu-latest
    steps:
      - name: Echo Pull Request Body
        run: |
          echo "Pull Request Body: ${{ github.event.pull_request.body }}"


```

```yaml
name: Pull Request Injection Test

on:
  pull_request:
    branches: [main]

jobs:
  process_pr:
    runs-on: ubuntu-latest
    steps:
      - name: Process PR Title
        run: |
          echo "PR Title: ${{ github.event.pull_request.title }}"

      - name: Process PR Body
        run: |
          echo "PR Body: ${{ github.event.pull_request.body }}"

      - name: Process Head Ref
        run: |
          echo "Head Ref: ${{ github.head_ref }}"

      - name: Process PR Head Label
        run: |
          echo "PR Label: ${{ github.event.pull_request.head.label }}"

```

```yaml
name: Array Trigger Format Test

on: [pull_request, push]

jobs:
  test_array_trigger:
    runs-on: ubuntu-latest
    steps:
      - name: Process PR with array format trigger
        run: |
          echo "PR Title: ${{ github.event.pull_request.title }}"
          echo "Branch: ${{ github.event.pull_request.head.ref }}"

```