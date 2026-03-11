---
title: "Known vulnerable actions"
group_id: "CICD / GitHub"
meta:
  name: "github/known_vulnerable_actions"
  id: "eb224cbc-fd0b-4b6b-8823-7e348133c41c"
  display_name: "Known vulnerable actions"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Supply-Chain"
---
## Metadata

**Id:** `eb224cbc-fd0b-4b6b-8823-7e348133c41c`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

### Description

Using a GitHub Action version that has a published security advisory can allow an attacker to execute arbitrary code in your CI environment or exfiltrate secrets and artifacts. This rule inspects workflow step `uses` clauses that reference repository actions using `owner/repo@ref` and queries GitHub's security advisories for the resolved tag or commit. Steps whose referenced tag or commit match a GHSA advisory are flagged. When the advisory provides a patched version, the audit suggests upgrading the `uses` value to that patched tag or to the corresponding commit hash.

Secure example:

```yaml
- name: Checkout
  uses: actions/checkout@v4
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

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: dist/

      - name: Download artifact
        uses: actions/download-artifact@v4
        with:
          name: build-output

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
        uses: actions/checkout@v2

      - name: Upload artifact with vulnerable action
        uses: actions/upload-artifact@v1
        with:
          name: build-output
          path: dist/

      - name: Download artifact
        uses: actions/download-artifact@v1
        with:
          name: build-output

```