---
title: "Unredacted secrets"
group_id: "CICD / GitHub"
meta:
  name: "github/unredacted_secrets"
  id: "c3d4e5f6-a7b8-49c0-d1e2-f3a4b5c6d7e8"
  display_name: "Unredacted secrets"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `c3d4e5f6-a7b8-49c0-d1e2-f3a4b5c6d7e8`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets)

### Description

Passing GitHub Actions secrets through transformation functions such as `fromJSON()` is unsafe. The transformation produces a different string that GitHub's automatic redaction can't recognize, which can allow secret values to appear in plaintext in workflow logs.

This rule flags workflow expressions that call `fromJSON` with the `secrets` context or any child of it as an argument, for example `fromJSON(secrets)`, `fromJSON(secrets.MY_SECRET)`, or nested uses like `fromJSON(secrets.MY_SECRET).field`. Avoid storing multiple values as a single JSON secret. Instead, store individual secrets and reference them directly, or ensure any transformed value is never written to logs or exposed to third-party actions.

Secure example — reference a single secret value instead of parsing a JSON blob:

```yaml
- name: Use secret directly
  run: ./deploy --db-password "${{ secrets.DB_PASSWORD }}"
```

## Compliant Code Examples
```yaml
name: Safe Secret Usage
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Use secret directly
        run: |
          echo "Using secret safely"
          curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com

```
## Non-Compliant Code Examples
```yaml
name: Unredacted Secret
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Parse secret as JSON
        run: |
          CONFIG='${{ fromJSON(secrets.CONFIG_JSON) }}'
          echo "Config: $CONFIG"

```