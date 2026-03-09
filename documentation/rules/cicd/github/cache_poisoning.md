---
title: "Cache poisoning"
group_id: "CICD / GitHub"
meta:
  name: "github/cache_poisoning"
  id: "e5f6a7b8-c9d0-41e2-f3a4-b5c6d7e8f9a0"
  display_name: "Cache poisoning"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Supply Chain"
---
## Metadata

**Id:** `e5f6a7b8-c9d0-41e2-f3a4-b5c6d7e8f9a0`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Supply Chain

#### Learn More

 - [Provider Reference](https://adnanthekhan.com/2024/05/06/breaking-rulesets-github-artifact-poisoning/)

### Description

Publishing workflows that build and publish runtime artifacts must not write to dependency caches because a poisoned cache can introduce malicious dependencies into packages, releases, or container images and lead to supply‑chain compromise. For example using writable caches exposed to pull request workflows. This rule inspects GitHub Actions workflow job steps: the `uses` key identifies cache‑aware actions. Examples include `actions/cache`, `actions/setup-go`, `actions/setup-node`, `actions/setup-python`, `Swatinem/rust-cache`, and others. It also identifies the `with` mapping containing cache-related controls. When a job is triggered by release events or contains well‑known publisher steps, ensure `cache-write` flags are disabled. For example, `lookup-only: true` for `actions/cache` and `cache: false` for boolean `cache` controls. Steps missing a disabling flag, explicitly enabling caching, or relying on an action’s default caching behaviour will be flagged; note that some actions use string-valued fields to control caching and non-configurable actions cannot be automatically fixed.

Secure examples:

```yaml
- uses: actions/cache@v4
  with:
    path: |
      ~/.cargo/registry
      ~/.cargo/git
    key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
    lookup-only: true
```

```yaml
- uses: actions/setup-go@v4
  with:
    go-version: '1.21'
    cache: false
```

## Compliant Code Examples
```yaml
name: Secure Publishing Workflow
on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: ''

      - run: npm ci

      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}

```
## Non-Compliant Code Examples
```yaml
name: Vulnerable Publishing Workflow
on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        name: vulnerable code
        with:
          node-version: '18'
          cache: 'npm'

      - run: npm ci

      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}

```