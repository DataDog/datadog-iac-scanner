---
title: "Overprovisioned secrets"
group_id: "CICD / GitHub"
meta:
  name: "github/overprovisioned_secrets"
  id: "b2c3d4e5-f6a7-48b9-c0d1-e2f3a4b5c6d7"
  display_name: "Overprovisioned secrets"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `b2c3d4e5-f6a7-48b9-c0d1-e2f3a4b5c6d7`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets)

### Description

Referencing the entire GitHub Actions `secrets` context or using dynamic/non-literal secret indexing exposes all repository secrets to the workflow runner. If a workflow or runner is compromised, an attacker could read every secret instead of only the ones required by the job. This rule flags expression patterns that serialize or expand the secrets object—specifically calls to `toJSON(secrets)` and context accesses like `secrets[<non-literal>]` where the index is not a literal string or number. Avoid these patterns and reference required secrets explicitly by literal property names, such as `secrets.MY_SECRET`. Expressions that call `toJSON(secrets)` or use non-literal secret indices will be flagged.

Secure usage example:

```yaml
env:
  MY_TOKEN: ${{ secrets.MY_TOKEN }}
steps:
  - name: Use token
    run: echo "${{ secrets.MY_TOKEN }}"
```

## Compliant Code Examples
```yaml
name: Proper Secret Usage
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy with specific secret
        run: |
          curl -H "Authorization: Bearer ${{ secrets.DEPLOY_TOKEN }}" \
               -H "API-Key: ${{ secrets.API_KEY }}" \
               https://api.example.com/deploy

```
## Non-Compliant Code Examples
```yaml
name: Overprovisioned Secrets
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Export all secrets
        run: echo '${{ toJSON(secrets) }}'

      - name: Dynamic secret access
        run: |
          SECRET_NAME="DEPLOY_TOKEN_${{ matrix.env }}"
          echo ${{ secrets[format('DEPLOY_TOKEN_{0}', matrix.env)] }}

```