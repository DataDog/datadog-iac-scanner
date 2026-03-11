---
title: "Forbidden uses"
group_id: "CICD / GitHub"
meta:
  name: "github/forbidden_uses"
  id: "14813ab9-cffa-40e3-87fb-66c5e9b07bdf"
  display_name: "Forbidden uses"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Supply-Chain"
---
## Metadata

**Id:** `14813ab9-cffa-40e3-87fb-66c5e9b07bdf`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

### Description

GitHub Actions steps must not invoke forbidden or untrusted actions because actions run with pipeline privileges. A compromised action can exfiltrate secrets, modify code, or execute arbitrary commands in your CI/CD environment.

This rule inspects the `uses` field of workflow step entries and evaluates repository-style references, such as `owner/repo@ref`, against the configured forbidden-uses policy. If the configuration is a whitelist (allow), only actions that match an allow pattern are permitted. If it is a blacklist (deny), any repository-style `uses` that matches a deny pattern will be flagged. Local actions referenced by a relative path, such as `./.github/actions/...`, are never denied. Docker image uses are not evaluated by this rule, and steps without a `uses` field are ignored.

Secure example:

```yaml
steps:
  - name: Checkout
    uses: actions/checkout@v3

  - name: Local helper
    uses: ./.github/actions/my-action
```

## Compliant Code Examples
```yaml
name: compliant-workflow

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Build application
        run: npm ci && npm run build

```
## Non-Compliant Code Examples
```yaml
name: insecure-workflow

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Use forbidden action
        uses: untrusted-org/suspicious-action@main

      - name: Build application
        run: npm ci && npm run build

```