---
title: "Secrets outside environment"
group_id: "CICD / GitHub"
meta:
  name: "github/secrets_outside_env"
  id: "a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6"
  display_name: "Secrets outside environment"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment)

### Description

Secrets referenced in GitHub Actions jobs should be scoped to a dedicated environment to limit their availability and reduce the blast radius if credentials are exposed. This rule inspects workflow job definitions and flags jobs that reference the `secrets` context in fenced expressions but do not define the `environment` property. It looks for `secrets.<NAME>` usages in expressions and excludes `secrets.GITHUB_TOKEN`, which is always available. Any job without an `environment` that accesses `secrets.*` will be reported.

Remediate by adding an `environment` to the job and moving sensitive values to environment-scoped secrets with appropriate approvals, or confirm that repository/org-level secrets are intentionally used.

## Compliant Code Examples
```yaml
name: Secrets in Environment
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Deploy with secrets
        run: |
          echo "Deploying..."
          curl -H "Authorization: Bearer ${{ secrets.DEPLOY_TOKEN }}" https://api.example.com/deploy

```
## Non-Compliant Code Examples
```yaml
name: Secrets Outside Environment
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy with secrets
        run: |
          echo "Deploying..."
          curl -H "Authorization: Bearer ${{ secrets.DEPLOY_TOKEN }}" https://api.example.com/deploy

```