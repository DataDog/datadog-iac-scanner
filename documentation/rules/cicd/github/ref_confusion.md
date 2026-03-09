---
title: "Ref confusion"
group_id: "CICD / GitHub"
meta:
  name: "github/ref_confusion"
  id: "85eef22b-9225-4745-8b17-dca1a8cd54d2"
  display_name: "Ref confusion"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Supply-Chain"
---
## Metadata

**Id:** `85eef22b-9225-4745-8b17-dca1a8cd54d2`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

### Description

GitHub Actions steps and reusable workflow calls that use ambiguous named git refs (for example `@foo`) can end up checking out different code if the upstream repository exposes the same name as both a branch and a tag, creating a supply‑chain risk or accidental execution of unreviewed code. Check the `uses` property on workflow steps, composite actions, and reusable workflow calls when it references a repository (`owner/repo@ref`); the ref should be immutable like a full commit SHA or explicitly namespace‑qualified, such as `refs/heads/<name>` or `refs/tags/<name>`. This rule flags `uses` entries where the ref is symbolic, because it is not a full commit SHA and the same name exists as both a branch and a tag in the referenced repository.

Secure examples: 

```yaml
# Pin to an immutable commit SHA
steps:
  - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567

# Or explicitly qualify the namespace to disambiguate
steps:
  - uses: owner/repo@refs/heads/main
```

## Compliant Code Examples
```yaml
name: compliant-workflow

on:
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Run tests
        run: npm test

```
## Non-Compliant Code Examples
```yaml
name: insecure-workflow

on:
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}

      - name: Run tests
        run: npm test

```