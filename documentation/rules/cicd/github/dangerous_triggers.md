---
title: "Dangerous triggers"
group_id: "CICD / GitHub"
meta:
  name: "github/dangerous_triggers"
  id: "a7b8c9d0-e1f2-43a4-b5c6-d7e8f9a0b1c2"
  display_name: "Dangerous triggers"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `a7b8c9d0-e1f2-43a4-b5c6-d7e8f9a0b1c2`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)

### Description

The `pull_request_target` and `workflow_run` triggers are dangerous because workflows using them run with the base repository's privileges and access to repository secrets. This allows untrusted pull requests or external workflow runs to exfiltrate secrets or modify repository contents.

Check GitHub Actions workflow definitions in `.github/workflows/*.yml` for the top-level `on` property containing `pull_request_target` or `workflow_run`. Any workflow that declares either trigger will be flagged.

Avoid these triggers when possible. Prefer `pull_request` for pull-request checks or manual/controlled triggers like `workflow_dispatch`. Configure minimal `permissions` for `GITHUB_TOKEN` and avoid using repository secrets in workflows that handle untrusted events.

If you must use these triggers, restrict event filters (branches/types), enforce least-privilege `permissions`, never expose secrets to untrusted runs, and validate event origin before performing privileged actions.

Secure alternatives example:

```yaml
on: [pull_request]

permissions:
  contents: read
  actions: read

# avoid using secrets in jobs triggered by external contributions
```

## Compliant Code Examples
```yaml
name: Safe Workflow
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test

```
## Non-Compliant Code Examples
```yaml
name: Dangerous Workflow
on: ["pull_request_target"]


jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test

```

```yaml
name: Dangerous Workflow
on: pull_request_target

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test

```

```yaml
name: Dangerous Workflow
on: workflow_run

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test

```