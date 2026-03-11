---
title: "Artipacked"
group_id: "CICD / GitHub"
meta:
  name: "github/artipacked"
  id: "c3d4e5f6-a7b8-49c0-d1e2-f3a4b5c6d7e8"
  display_name: "Artipacked"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Supply Chain"
---
## Metadata

**Id:** `c3d4e5f6-a7b8-49c0-d1e2-f3a4b5c6d7e8`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Supply Chain

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets)

### Description

Persisting runner credentials into the workspace can leak the `GITHUB_TOKEN` via uploaded artifacts or repository files, exposing secrets to anyone who can access those artifacts. For steps that use `actions/checkout`, the `with.persist-credentials` property must be defined and set to `false`. Steps missing this property or with `persist-credentials: true` will be flagged.

Findings are escalated when an `actions/upload-artifact` step uploads dangerous paths such as `.`/`./`/`..`/`../` or an expression that references `github.workspace`, since those artifacts can include the persisted credentials. In that case, the checkout and the upload are reported together with higher confidence.

Starting with `actions/checkout@v6`, credentials are stored in `$RUNNER_TEMP` instead of `.git/config`, so the rule lowers severity for v6+ checkouts when no vulnerable uploads are present. When the checkout ref is a commit SHA, the auditor attempts to resolve its tag via the GitHub client and treats unresolved or unknown versions conservatively as older versions.

Secure configuration example:

```yaml
- uses: actions/checkout@v4
  with:
    persist-credentials: false
```

## Compliant Code Examples
```yaml
name: Secure Artifact Upload
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with persist-credentials disabled
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Build
        run: npm run build

      - name: Upload specific build artifacts
        uses: actions/upload-artifact@v3
        with:
          name: dist
          path: dist/

```
## Non-Compliant Code Examples
```yaml
name: Insecure Artifact Upload
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with credentials persisted
        uses: actions/checkout@v4

      - name: Build
        run: npm run build

      - name: Upload entire workspace
        uses: actions/upload-artifact@v3
        with:
          name: workspace
          path: .

```