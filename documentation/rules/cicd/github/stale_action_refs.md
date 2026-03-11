---
title: "Stale action refs"
group_id: "CICD / GitHub"
meta:
  name: "github/stale_action_refs"
  id: "7ef4d5a1-2337-4a71-9c67-3ffe445b37e4"
  display_name: "Stale action refs"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Supply-Chain"
---
## Metadata

**Id:** `7ef4d5a1-2337-4a71-9c67-3ffe445b37e4`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

### Description

Workflow steps should not pin actions to raw commit SHAs that lack an associated Git tag. Untagged commits have no release metadata and are more likely to contain unpublished, unreviewed, or unmaintained changes that increase supply-chain and reliability risk. This rule inspects workflow step `uses` entries that reference a repository in the form `owner/repo@ref` and flags cases where the ref is a commit hash and the GitHub API reports no tag pointing to that commit. Prefer pinning to an official Git tag or release, such as `v1.2.3` or a stable major tag like `v1`. Steps with commit refs that do not map to any tag will be flagged as stale.

Secure examples:

```yaml
- name: Checkout
  uses: actions/checkout@v3

- name: Use custom action
  uses: owner/repo@v1.2.3
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
        uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Cache dependencies
        uses: actions/cache@v4
        with:
          path: ~/.npm
          key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}

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
      - name: Checkout code with old version
        uses: actions/checkout@v1

      - name: Setup Node with old version
        uses: actions/setup-node@v1
        with:
          node-version: '20'

      - name: Cache dependencies with old version
        uses: actions/cache@v1
        with:
          path: ~/.npm
          key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}

```