---
title: "Self-hosted runner"
group_id: "CICD / GitHub"
meta:
  name: "github/self_hosted_runner"
  id: "cicd-github-self-hosted-runner"
  display_name: "Self-hosted runner"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}cicd-github-self-hosted-runner{{< /copyable-code >}}

**Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security)

### Description

Self-hosted runners in public repositories are risky because they can retain state, files, or credentials between workflow runs. They also allow untrusted contributors (for example via pull requests) to access secrets or modify the runner environment.

Inspect the GitHub Actions workflow job `runs-on` setting. Any job whose `runs-on` value begins with the literal `self-hosted`, references a runner group, or uses expressions/matrix expansions that may evaluate to `self-hosted` should be reviewed or avoided in public repos.

Prefer explicit GitHub-hosted runner labels such as `ubuntu-latest` for public workflows. Expression-based or group-based runner selections are flagged because they may expand to self-hosted runners at runtime.

Secure example using a GitHub-hosted runner:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
```

## Compliant Code Examples
```yaml
name: GitHub Hosted Runner
on: push

jobs:
  # Should NOT trigger: GitHub-hosted runner
  test_github_hosted:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  # Should NOT trigger: Array of GitHub-hosted runners
  test_github_hosted_array:
    runs-on: [ubuntu-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  # Should NOT trigger: Matrix without self-hosted
  test_matrix_no_self_hosted:
    strategy:
      matrix:
        runner: [ubuntu-latest, windows-latest, macos-latest]
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  # Should NOT trigger: Expression that doesn't reference runner
  test_expression_not_runner:
    runs-on: ubuntu-latest
    steps:
      - name: Test with expression
        run: echo "${{ github.sha }}"

```
## Non-Compliant Code Examples
```yaml
name: Self Hosted Runner
on: push

jobs:
  # Case 1: Literal self-hosted in array
  test:
    runs-on: [self-hosted, linux, x64]
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  # Case 2a: Expression-based runner (string) - matrix with self-hosted
  test_matrix_expression:
    strategy:
      matrix:
        runner: [self-hosted, ubuntu-latest]
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  # Case 2b: Expression-based runner (array) - variable reference
  test_expression_array:
    runs-on: ["${{ inputs.runner }}"]
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  # Case 2c: Expression-based runner (string) - simple expression
  test_expression_string:
    runs-on: ${{ github.event.inputs.runner }}
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  # Case 3: Runner group (implies self-hosted)
  test_runner_group:
    runs-on:
      group: my-runner-group
    steps:
      - uses: actions/checkout@v4
      - run: npm test

```