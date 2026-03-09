---
title: "Self-hosted runner"
group_id: "CICD / GitHub"
meta:
  name: "github/self_hosted_runner"
  id: "b8c9d0e1-f2a3-44b5-c6d7-e8f9a0b1c2d3"
  display_name: "Self-hosted runner"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `b8c9d0e1-f2a3-44b5-c6d7-e8f9a0b1c2d3`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security)

### Description

Self-hosted runners in public repositories are risky because they can retain state, files, or credentials between workflow runs and allow untrusted contributors (for example via pull requests) to access secrets or modify the runner environment. Inspect the GitHub Actions workflow job `runs-on` setting: any job whose `runs-on` value begins with the literal `self-hosted`, references a runner group, or uses expressions/matrix expansions that may evaluate to `self-hosted` should be reviewed or avoided in public repos. Prefer explicit GitHub-hosted runner labels such as `ubuntu-latest` for public workflows; expression-based or group-based runner selections are flagged because they may expand to self-hosted runners at runtime.

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
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test

```
## Non-Compliant Code Examples
```yaml
name: Self Hosted Runner
on: push

jobs:
  test:
    runs-on: [self-hosted, linux, x64]
    steps:
      - uses: actions/checkout@v4
      - run: npm test

```