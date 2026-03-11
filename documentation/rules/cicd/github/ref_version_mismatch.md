---
title: "Ref version mismatch"
group_id: "CICD / GitHub"
meta:
  name: "github/ref_version_mismatch"
  id: "969976c1-f152-4d77-abaa-1d051e449fc7"
  display_name: "Ref version mismatch"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Supply-Chain"
---
## Metadata

**Id:** `969976c1-f152-4d77-abaa-1d051e449fc7`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

### Description

Version comments in GitHub Actions workflows should accurately reflect the release tag that corresponds to a pinned commit SHA. A mismatched comment can mislead reviewers and may hide supply-chain tampering or misconfiguration that substitutes different code while appearing to use a trusted version.

This rule inspects workflow step `uses` entries that reference a repository with a commit ref, written repository@<commit_sha>, and looks for version comments on the same `uses` YAML node matching patterns like `# v1.2.3`, `# tag=1.2.3`, or `# version: 1.2.3`. If a version comment is present, the tag is resolved via the GitHub API and must point to the same commit as the pinned SHA. The step is flagged when the tag resolves to a different commit. Steps using symbolic refs such as `@v1.0.0` are not checked. The rule currently does not flag comments that cannot be resolved to any tag.

Secure configuration example:

```yaml
- name: Checkout with matching comment
  uses: actions/checkout@a81bbbf8298c0fa03ea29cdc80d8d0ce8b6c2f2c # v3.0.2
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
      - name: Checkout code with version mismatch
        uses: actions/checkout@v4.1.0

      - name: Setup Node with mismatched SHA
        uses: actions/setup-node@v4.0.0
        with:
          node-version: '20'

```