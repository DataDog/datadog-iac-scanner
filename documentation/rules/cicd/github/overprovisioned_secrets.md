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

**Id:** {{</* copyable-code */>}}b2c3d4e5-f6a7-48b9-c0d1-e2f3a4b5c6d7{{</* copyable-code */>}}

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets)

### Description

Referencing the entire GitHub Actions `secrets` context or using dynamic/non-literal secret indexing exposes all repository secrets to the workflow runner. If a workflow or runner is compromised, an attacker could read every secret instead of only the ones required by the job.

This rule flags expression patterns that serialize or expand the secrets object—specifically calls to `toJSON(secrets)` and context accesses like `secrets[<non-literal>]` where the index is not a literal string or number. Reference required secrets explicitly by literal property names, such as `secrets.MY_SECRET`. Expressions that call `toJSON(secrets)` or use non-literal secret indices will be flagged.

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
    # Proper: individual secret in job-level env
    env:
      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
      API_KEY: ${{ secrets.API_KEY }}
    # Proper: individual secret check in job-level if
    if: ${{ secrets.DEPLOY_TOKEN != '' }}
    steps:
      # Proper: individual secrets in step run block
      - name: Deploy with specific secret
        run: |
          curl -H "Authorization: Bearer ${{ secrets.DEPLOY_TOKEN }}" \
               -H "API-Key: ${{ secrets.API_KEY }}" \
               https://api.example.com/deploy

      # Proper: individual secret in step-level if
      - name: Conditional deployment
        if: ${{ secrets.PRODUCTION_KEY != '' }}
        run: echo "Deploying to production"

      # Proper: individual secrets in step env block
      - name: Step with environment variables
        env:
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
          SMTP_PASSWORD: ${{ secrets.SMTP_PASSWORD }}
        run: echo "Configured environment"

      # Proper: individual secret in step with block
      - name: Use action with secret
        uses: some/action@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          api_key: ${{ secrets.API_KEY }}

      # Proper: matrix with literal values (not dynamic secret indexing)
      - name: Deploy to environment
        run: echo "Deploying with ${{ secrets.DEPLOY_TOKEN }}"

      # Proper: toJSON on non-secret contexts
      - name: Use toJSON on env
        run: echo '${{ toJSON(env) }}'

      # Proper: toJSON on github context
      - name: Use toJSON on github context
        run: echo '${{ toJSON(github.event) }}'

```
## Non-Compliant Code Examples
```yaml
name: Overprovisioned Secrets
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    # toJSON(secrets) in job-level env block
    env:
      ALL_SECRETS: ${{ toJSON(secrets) }}
    # toJSON(secrets) in job-level if condition
    if: ${{ toJSON(secrets) != '{}' }}
    steps:
      # toJSON(secrets) in step run block
      - name: Export all secrets
        run: echo '${{ toJSON(secrets) }}'

      # Dynamic secret indexing in step run block
      - name: Dynamic secret access
        run: |
          SECRET_NAME="DEPLOY_TOKEN_${{ matrix.env }}"
          echo ${{ secrets[format('DEPLOY_TOKEN_{0}', matrix.env)] }}

      # toJSON(secrets) in step-level if condition
      - name: Check secrets with toJSON
        if: ${{ toJSON(secrets) != '{}' }}
        run: echo "Has secrets"

      # Dynamic secret indexing in step-level if condition
      - name: Check dynamic secret
        if: ${{ secrets[format('KEY_{0}', github.event.inputs.env)] != '' }}
        run: echo "Secret exists"

      # toJSON(secrets) in step env block
      - name: Step with env secrets
        env:
          SECRETS_JSON: ${{ toJSON(secrets) }}
        run: echo "Processing secrets"

      # Dynamic indexing in step env block
      - name: Step with dynamic env
        env:
          DYNAMIC_SECRET: ${{ secrets[github.event.inputs.secret_name] }}
        run: echo "Using dynamic secret"

      # toJSON(secrets) in step with block
      - name: Action with toJSON secrets
        uses: some/action@v1
        with:
          config: ${{ toJSON(secrets) }}

      # Dynamic indexing in step with block
      - name: Action with dynamic secret
        uses: another/action@v1
        with:
          token: ${{ secrets[matrix.secret_key] }}

  another-job:
    runs-on: ubuntu-latest
    # Dynamic indexing in job-level env block
    env:
      TOKEN: ${{ secrets[format('TOKEN_{0}', github.ref_name)] }}
    # Dynamic indexing in job-level if condition
    if: ${{ secrets[github.event.inputs.key] != '' }}
    steps:
      - run: echo "Running"

```

```yaml
name: dogfood-overprovisioned-secrets-noncompliant-workflow-env
on:
  workflow_dispatch: {}

env:
  ALL_SECRETS: ${{ toJSON(secrets) }}
  DYNAMIC_SECRET: ${{ secrets[matrix.secret_key] }}

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo "inherits env; entire secrets JSON is available to the job"

```