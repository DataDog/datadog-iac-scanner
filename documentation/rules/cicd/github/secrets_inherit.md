---
title: "Secrets inherit"
group_id: "CICD / GitHub"
meta:
  name: "github/secrets_inherit"
  id: "cicd-github-secrets-inherit"
  display_name: "Secrets inherit"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `cicd-github-secrets-inherit`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/using-workflows/reusing-workflows#passing-secrets-to-nested-workflows)

### Description

Using `secrets: inherit` in reusable workflow calls passes all secrets from the calling workflow to the called workflow. This violates the principle of least privilege and can lead to broad secret exposure if the reusable workflow is compromised or contains vulnerabilities.

The `secrets` property on a job that invokes a reusable workflow (a job with `uses: <owner>/<repo>/.github/workflows/<file>@<ref>`) must not be set to `inherit`. Jobs with `secrets: inherit` will be flagged. Instead, explicitly map only the specific secrets the reusable workflow requires using the secrets mapping syntax, or omit the `secrets` property if none are needed.

Secure example with explicit secret mapping:

```yaml
jobs:
  call-reusable:
    uses: org/repo/.github/workflows/reusable.yml@v1
    secrets:
      API_TOKEN: ${{ secrets.API_TOKEN }}
      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
```

## Compliant Code Examples
```yaml
name: Secure Reusable Workflow Call
on: push

jobs:
  call-workflow:
    uses: ./.github/workflows/reusable.yml
    secrets:
      token: ${{ secrets.DEPLOY_TOKEN }}
      api_key: ${{ secrets.API_KEY }}
    steps: "none"

```
## Non-Compliant Code Examples
```yaml
name: Insecure Reusable Workflow Call
on: push

jobs:
  call-workflow:
    uses: ./.github/workflows/reusable.yml
    secrets: inherit
    steps: "none"

```