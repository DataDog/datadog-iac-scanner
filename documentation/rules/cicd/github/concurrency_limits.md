---
title: "Concurrency limits"
group_id: "CICD / GitHub"
meta:
  name: "github/concurrency_limits"
  id: "f6a7b8c9-d0e1-42f3-a4b5-c6d7e8f9a0b1"
  display_name: "Concurrency limits"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `f6a7b8c9-d0e1-42f3-a4b5-c6d7e8f9a0b1`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#concurrency)

### Description

Workflows and jobs without proper concurrency controls can lead to redundant, overlapping runs that waste CI/CD compute, increase queue times, and slow feedback for developers when commits or PR updates happen frequently. Configure the `concurrency` setting with `cancel-in-progress: true` so GitHub cancels in-progress runs for the same concurrency group instead of running duplicates. In workflow YAML, the `concurrency` property must be an object containing a `group` and `cancel-in-progress: true`; this rule flags workflows or jobs that omit `concurrency` or use a bare string value, which therefore lacks `cancel-in-progress`. Reusable-only workflows should not manage concurrency themselves; their callers should define concurrency to avoid deadlocks and premature cancellations.

Secure configuration example:

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

## Compliant Code Examples
```yaml
name: Workflow with Concurrency Control
on: pull_request

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test

```
## Non-Compliant Code Examples
```yaml
name: Workflow without Cancel in Progress
on: pull_request

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test

```