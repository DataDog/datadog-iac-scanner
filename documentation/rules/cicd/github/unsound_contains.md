---
title: "Unsound contains"
group_id: "CICD / GitHub"
meta:
  name: "github/unsound_contains"
  id: "e5f6a7b8-c9d0-41e2-f3a4-b5c6d7e8f9a0"
  display_name: "Unsound contains"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `e5f6a7b8-c9d0-41e2-f3a4-b5c6d7e8f9a0`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/learn-github-actions/expressions#contains)

### Description

Using `contains()` with a delimiter or space-separated literal to validate a runtime value is unsafe because `contains()` does substring matching, allowing crafted values, such as `refs/heads/main/malicious` or `refs/heads/main` to satisfy the check and bypass intended restrictions. This is especially dangerous when the value being tested comes from user-controllable contexts, such as `env.*`, `github.ref`, `github.ref_name`, `github.head_ref`, `github.base_ref`, `github.actor`, `github.sha`, `github.triggering_actor`, or `inputs.*` because an attacker can trigger unintended workflow paths, disclosures, or privileged actions. The rule inspects job `if` expressions and flags calls of the form `contains(<string literal>, <Context>)`. Replace substring checks with explicit equality comparisons, such as `github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop'` or use a JSON array with `fromJSON` and `contains`, for example:

```yaml
# Explicit equality checks
if: github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop'

# Or use a JSON array for exact membership testing
if: contains(fromJSON('["refs/heads/main","refs/heads/develop"]'), github.ref)
```

## Compliant Code Examples
```yaml
name: Sound Contains Usage
on: pull_request

jobs:
  test:
    runs-on: ubuntu-latest
    if: ${{ github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop' }}
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  test-with-json:
    runs-on: ubuntu-latest
    if: ${{ contains(fromJSON('["refs/heads/main", "refs/heads/develop"]'), github.ref) }}
    steps:
      - uses: actions/checkout@v4
      - run: npm test

```
## Non-Compliant Code Examples
```yaml
name: Unsound Contains Usage
on: pull_request

jobs:
  test:
    runs-on: ubuntu-latest
    if: ${{ contains('refs/heads/main refs/heads/develop', github.ref) }}
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  test-env:
    runs-on: ubuntu-latest
    if: ${{ contains('production staging', env.ENVIRONMENT) }}
    steps:
      - run: echo "Deploying"

```