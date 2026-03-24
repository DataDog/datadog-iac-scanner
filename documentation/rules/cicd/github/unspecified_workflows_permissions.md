---
title: "Unspecified workflows level permissions"
group_id: "CICD / GitHub"
meta:
  name: "github/unspecified_workflows_permissions"
  id: "d946b13a-0b2b-49c5-b560-45b9666373e1"
  display_name: "Unspecified workflows level permissions"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `d946b13a-0b2b-49c5-b560-45b9666373e1`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#permissions)

### Description

Workflows or jobs that do not explicitly define the GitHub Actions `permissions` mapping leave the `GITHUB_TOKEN` with repository default scopes, increasing the blast radius if the token is compromised and enabling unintended access. The `permissions` property must be set either at the workflow root or per job to declare least-privilege scopes for the `GITHUB_TOKEN`. This rule flags workflows missing the top-level `permissions` when all jobs also omit permissions, and it flags individual jobs that lack `permissions` when other jobs in the same workflow do define them. Define only the scopes required by the workflow or job, for example `contents: read` and `packages: read`, to minimize access.

Secure workflow-level and job-level examples:

```yaml
# Workflow-level permissions
permissions:
  contents: read
  packages: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "build"

  publish:
    permissions:
      contents: read
      packages: write
    runs-on: ubuntu-latest
    steps:
      - run: echo "publish"
```

## Compliant Code Examples
```yaml
name: true-negative-workflow-level
on:
  push:
    branches:
      - main
  pull_request:

permissions:
  contents: read

jobs:
  linter:
    runs-on: ubuntu-latest
    steps:
      - name: Harden Runner
        uses: step-security/harden-runner@8ca2b8b2ece13480cda6dacd3511b49857a23c09
        with:
          egress-policy: block
          allowed-endpoints: >
            api.github.com:443
            github.com:443

      - name: Setup Golang
        uses: actions/setup-go@93397bea11091df50f3d7e59dc26a7711a8bcfbe
        with:
          go-version: "1.22"

      - name: Checkout Git Repo
        uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab

      - name: golangci-lint
        uses: golangci/golangci-lint-action@3a919529898de77ec3da873e3063ca4b10e7f5cc
        with:
          version: v1.56.2
          args: ./...

```

```yaml
name: per-job-true-negative
on:
  push:
    branches:
      - main

jobs:
  test:
    runs-on: ubuntu-latest
    uses: ./.github/workflows/pr-test.yml
    with:
      repo: core
    secrets: inherit
    permissions:
      contents: read

  lint:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v2
    permissions:
      contents: read

```
## Non-Compliant Code Examples
```yaml
name: per-job-true-positive
on:
  push:
    branches:
      - main

jobs:
  test:
    runs-on: ubuntu-latest
    uses: ./.github/workflows/pr-test.yml
    with:
      repo: core
    secrets: inherit
    permissions:
      contents: read

  lint:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v2

```

```yaml
name: true-positive-no-permissions
on:
  push:
    branches:
      - main
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v2

      - name: Run tests
        run: npm test

  lint:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v2

      - name: Run linter
        run: npm run lint

```