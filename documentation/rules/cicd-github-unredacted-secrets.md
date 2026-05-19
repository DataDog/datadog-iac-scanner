---
title: "Unredacted secrets"
group_id: "CICD / GitHub"
meta:
  name: ""github/unredacted_secrets""
  id: "cicd-github-unredacted-secrets"
  display_name: "Unredacted secrets"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}cicd-github-unredacted-secrets{{< /copyable-code >}}

**Provider:** GitHub

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
  # Case 1: Direct secret usage (safe - GitHub can redact this)
  test_direct_secret:
    runs-on: ubuntu-latest
    steps:
      - name: Use secret directly
        run: |
          echo "Using secret safely"
          curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com

  # Case 2: fromJSON with non-secret context (safe - not a secret)
  test_fromjson_env:
    runs-on: ubuntu-latest
    steps:
      - name: Parse environment variable
        env:
          CONFIG: ${{ fromJSON(env.CONFIG_JSON) }}
        run: echo "Config parsed"

  # Case 3: fromJSON with literal string (safe - no secret)
  test_fromjson_literal:
    runs-on: ubuntu-latest
    steps:
      - name: Parse literal JSON
        run: echo '${{ fromJSON('{"key": "value"}') }}'

  # Case 4: fromJSON with inputs (safe - workflow inputs)
  test_fromjson_inputs:
    runs-on: ubuntu-latest
    steps:
      - name: Parse workflow input
        run: echo '${{ fromJSON(inputs.config) }}'

  # Case 5: toJSON with secrets (different issue - not covered by this rule)
  test_tojson_secrets:
    runs-on: ubuntu-latest
    steps:
      - name: Convert to JSON
        run: echo '${{ toJSON(secrets) }}'

  # Case 6: Secret in env block directly (safe)
  test_env_direct:
    runs-on: ubuntu-latest
    steps:
      - name: Environment variable
        env:
          API_KEY: ${{ secrets.API_KEY }}
        run: echo "Key is set"

  # Case 7: Multiple secrets used directly (safe)
  test_multiple_direct:
    runs-on: ubuntu-latest
    steps:
      - name: Multiple direct secrets
        env:
          KEY1: ${{ secrets.KEY1 }}
          KEY2: ${{ secrets.KEY2 }}
        run: echo "Keys configured"

  # Case 8: fromJSON with github context (safe - not secrets)
  test_fromjson_github:
    runs-on: ubuntu-latest
    steps:
      - name: Parse GitHub context
        run: echo '${{ fromJSON(github.event.client_payload.data) }}'

  # Case 9: Secret used in conditional (safe)
  test_conditional_direct:
    runs-on: ubuntu-latest
    steps:
      - name: Conditional on secret existence
        if: ${{ secrets.DEPLOY_KEY != '' }}
        run: echo "Deploy key exists"

  # Case 10: Other transformation functions (not fromJSON)
  test_other_functions:
    runs-on: ubuntu-latest
    steps:
      - name: Use other functions
        run: |
          echo '${{ format('Bearer {0}', secrets.TOKEN) }}'
          echo '${{ contains(secrets.ALLOWED_USERS, github.actor) }}'

```
## Non-Compliant Code Examples
```yaml
name: Unredacted Secret
on: push

jobs:
  # Case 1: fromJSON in run command
  test_run_command:
    runs-on: ubuntu-latest
    steps:
      - name: Parse secret as JSON in run
        run: |
          CONFIG='${{ fromJSON(secrets.CONFIG_JSON) }}'
          echo "Config: $CONFIG"

  # Case 2: fromJSON with lowercase (case insensitive)
  test_lowercase:
    runs-on: ubuntu-latest
    steps:
      - name: Lowercase fromjson
        run: echo '${{ fromjson(secrets.DATA) }}'

  # Case 3: fromJSON with property access
  test_property_access:
    runs-on: ubuntu-latest
    steps:
      - name: Access property of JSON secret
        run: echo '${{ fromJSON(secrets.CONFIG).apiKey }}'

  # Case 4: fromJSON with nested property access
  test_nested_property:
    runs-on: ubuntu-latest
    steps:
      - name: Access nested property
        run: echo '${{ fromJSON(secrets.SETTINGS).database.host }}'

  # Case 5: fromJSON in env block
  test_env_block:
    runs-on: ubuntu-latest
    steps:
      - name: Use in environment variable
        env:
          CONFIG: ${{ fromJSON(secrets.ENV_CONFIG) }}
        run: echo "Using config"

  # Case 6: fromJSON in with block
  test_with_block:
    runs-on: ubuntu-latest
    steps:
      - name: Use in action parameter
        uses: some/action@v1
        with:
          config: ${{ fromJSON(secrets.ACTION_CONFIG) }}

  # Case 7: fromJSON in if condition
  test_if_condition:
    runs-on: ubuntu-latest
    steps:
      - name: Conditional step
        if: ${{ fromJSON(secrets.FEATURE_FLAGS).enabled }}
        run: echo "Feature enabled"

  # Case 8: Multiple fromJSON calls
  test_multiple:
    runs-on: ubuntu-latest
    steps:
      - name: Multiple secret transformations
        run: |
          echo '${{ fromJSON(secrets.CONFIG1) }}'
          echo '${{ fromJSON(secrets.CONFIG2) }}'

```