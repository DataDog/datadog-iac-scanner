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

Workflows and jobs without proper concurrency controls can lead to redundant, overlapping runs that waste CI/CD compute, increase queue times, and slow feedback for developers when commits or PR updates happen frequently. Configure the `concurrency` setting with `cancel-in-progress: true` so GitHub cancels in-progress runs for the same concurrency group instead of running duplicates.

In workflow YAML, the `concurrency` property must be an object containing a `group` and `cancel-in-progress: true`. This rule flags workflows or jobs that omit `concurrency` or use a bare string value, which lacks `cancel-in-progress`. Reusable-only workflows should not manage concurrency themselves. Their callers should define concurrency to avoid deadlocks and premature cancellations.

Secure configuration example:

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

## Compliant Code Examples
```yaml
# Workflow with proper concurrency control
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
---
# Reusable workflow (should be skipped)
name: Reusable Workflow
on: workflow_call

concurrency:
  group: reusable-${{ github.ref }}

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm build
---
# Job-level concurrency with cancel-in-progress
name: Job Level Concurrency
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    concurrency:
      group: test-${{ github.ref }}
      cancel-in-progress: true
    steps:
      - uses: actions/checkout@v4
      - run: npm test
---
# Reusable workflow call (should be skipped)
name: Workflow Calling Reusable
on: push

concurrency:
  group: caller-${{ github.ref }}
  cancel-in-progress: true

jobs:
  call-reusable:
    uses: ./.github/workflows/reusable.yml

```
## Non-Compliant Code Examples
```yaml
# String-based concurrency (bare string, no cancel-in-progress)
name: String Concurrency
on: push

concurrency: ci-${{ github.ref }}

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm build

```

```yaml
name: Workflow without Cancel in Progress
on: pull_request

# Workflow-level concurrency without cancel-in-progress
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
---
# Job-level concurrency without cancel-in-progress
name: Job Level Concurrency
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    concurrency:
      group: test-${{ github.ref }}
    steps:
      - uses: actions/checkout@v4
      - run: npm test
---
# Missing concurrency at both levels
name: No Concurrency
on: pull_request

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run deploy

```