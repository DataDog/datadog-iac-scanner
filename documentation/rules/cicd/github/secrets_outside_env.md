---
title: "Secrets outside environment"
group_id: "CICD / GitHub"
meta:
  name: "github/secrets_outside_env"
  id: "cicd-common-secrets-outside-environment"
  display_name: "Secrets outside environment"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `cicd-common-secrets-outside-environment`

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
    # Proper: job has environment defined, so secrets are scoped
    environment: production
    env:
      API_KEY: ${{ secrets.API_KEY }}
    if: ${{ secrets.DEPLOY_TOKEN != '' }}
    steps:
      # Proper: secrets used within environment
      - name: Deploy with secrets
        run: |
          echo "Deploying..."
          curl -H "Authorization: Bearer ${{ secrets.DEPLOY_TOKEN }}" https://api.example.com/deploy

      # Proper: step-level if with secret within environment
      - name: Check production key
        if: ${{ secrets.PRODUCTION_KEY != '' }}
        run: echo "Has production key"

      # Proper: step env with secret within environment
      - name: Step with env secret
        env:
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
        run: echo "Configured database"

      # Proper: step with block with secret within environment
      - name: Action with secret
        uses: some/action@v1
        with:
          token: ${{ secrets.SERVICE_TOKEN }}
          api_key: ${{ secrets.API_KEY }}

  staging:
    runs-on: ubuntu-latest
    # Proper: another job with environment
    environment: staging
    env:
      STAGING_KEY: ${{ secrets.STAGING_KEY }}
    if: ${{ secrets.STAGING_TOKEN != '' }}
    steps:
      - run: echo "Deploying to staging"

  # Proper: reusable workflow calls are skipped
  call-workflow:
    uses: ./.github/workflows/deploy.yml
    secrets:
      token: ${{ secrets.DEPLOY_TOKEN }}

  # Proper: job without secrets doesn't trigger the rule
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm build

  # Proper: using GITHUB_TOKEN is allowed (explicitly excluded in the rule)
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with GITHUB_TOKEN
        run: |
          curl -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}" \
               https://api.github.com/repos/${{ github.repository }}

```
## Non-Compliant Code Examples
```yaml
name: Secrets Outside Environment
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    # Secret used in job-level env without environment
    env:
      API_KEY: ${{ secrets.API_KEY }}
    # Secret used in job-level if without environment
    if: ${{ secrets.DEPLOY_TOKEN != '' }}
    steps:
      # Secret used in step run block without environment
      - name: Deploy with secrets
        run: |
          echo "Deploying..."
          curl -H "Authorization: Bearer ${{ secrets.DEPLOY_TOKEN }}" https://api.example.com/deploy

      # Secret used in step-level if without environment
      - name: Check secret
        if: ${{ secrets.PRODUCTION_KEY != '' }}
        run: echo "Has production key"

      # Secret used in step env block without environment
      - name: Step with env secret
        env:
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
        run: echo "Configured database"

      # Secret used in step with block without environment
      - name: Action with secret
        uses: some/action@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          api_key: ${{ secrets.SERVICE_KEY }}

  another-job:
    runs-on: ubuntu-latest
    # Another job-level env without environment
    env:
      TOKEN: ${{ secrets.SERVICE_TOKEN }}
    # Another job-level if without environment
    if: ${{ secrets.ADMIN_KEY != '' }}
    steps:
      - run: echo "Running"

```