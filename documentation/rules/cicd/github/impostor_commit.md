---
title: "Impostor commit"
group_id: "CICD / GitHub"
meta:
  name: "github/impostor_commit"
  id: "ffe0b305-060f-45dc-87dc-7796bb442fd9"
  display_name: "Impostor commit"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Supply-Chain"
---
## Metadata

**Id:** `ffe0b305-060f-45dc-87dc-7796bb442fd9`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

### Description

GitHub Actions workflows must not reference commit SHA pins that are not present in the referenced owner/repo. Such "impostor" commits can resolve from forks or unrelated repositories, allowing attacker-controlled code to run in your CI/CD pipeline.

This rule inspects the `uses` property on job steps, reusable workflow calls, and composite steps when pinned to a commit SHA (format: `owner/repo@<commit>`). It flags cases where the specified commit SHA is not found in the target repository's tags, branches, or any named ref. Resources missing a matching tag/branch or where the commit is only resolvable via GitHub's fork network—because it is not in the target repo's history—will be reported as impostor commits.

Prefer pinning to a validated tag or branch, such as a semantically versioned tag.

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/hello-world-javascript-action@v1.1
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
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Setup Node
        uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8
        with:
          node-version: '20'

      - name: Build application
        run: npm ci && npm run build

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
        uses: actions/checkout@0000000000000000000000000000000000000000

      - name: Setup Node
        uses: actions/setup-node@1111111111111111111111111111111111111111
        with:
          node-version: '20'

      - name: Build application
        run: npm ci && npm run build

```