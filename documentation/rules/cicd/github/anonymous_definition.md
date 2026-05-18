---
title: "Anonymous definition"
group_id: "CICD / GitHub"
meta:
  name: "github/anonymous_definition"
  id: "cicd-github-anonymous-definition"
  display_name: "Anonymous definition"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** {{< copyable-code >}}cicd-github-anonymous-definition{{< /copyable-code >}}

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#name)

### Description

Unnamed workflows and jobs reduce traceability and slow down auditing, monitoring, and incident response because run logs and alerts become harder to identify and correlate.

Check GitHub Actions workflow YAML: the top-level `name` property must be defined and non-empty, and each standard job under `jobs` should include a non-empty `name` property. Workflows missing a top-level `name` or jobs without `name` will be flagged.

This rule applies to normal jobs. Reusable or composite actions may be treated differently by some tools, so ensure each visible job has a clear `name`. Use concise, descriptive names so runs and failures are immediately recognizable.

Secure example:

```yaml
name: CI — Build and Test

on:
  push:
    branches: [ main ]

jobs:
  build:
    name: Build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
```

## Compliant Code Examples
```yaml
name: Valid Workflow with Names
on: push

jobs:
  build:
    name: Build Job
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Run tests
        run: npm test

```
## Non-Compliant Code Examples
```yaml
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - run: npm test

```