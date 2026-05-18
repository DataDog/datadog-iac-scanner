---
title: "Unsound contains without controllable input"
group_id: "CICD / GitHub"
meta:
  name: "github/unsound_contains_no_controllable_input"
  id: "cicd-github-unsound-contains-no-controllable-input"
  display_name: "Unsound contains without controllable input"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "LOW"
  category: "Insecure Defaults"
---
## Metadata

**Id:** {{< copyable-code >}}cicd-github-unsound-contains-no-controllable-input{{< /copyable-code >}}

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Low

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/learn-github-actions/expressions#contains)

### Description

Using `contains()` with a string literal to validate a non-controllable value is unsafe because `contains()` performs substring matching. Crafted values such as `refs/heads/mai` or `ain` can satisfy the check and bypass intended restrictions.

The rule inspects job `if` expressions and flags calls of the form `contains(<string literal>, <Context>)`. Replace substring checks with explicit equality comparisons such as `github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop'`, or use a JSON array with `fromJSON` and `contains`.

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
  # Case 1: Explicit equality checks (best practice)
  test_explicit_equality:
    runs-on: ubuntu-latest
    if: ${{ github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop' }}
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  # Case 2: JSON array with contains() (safe approach)
  test_json_array:
    runs-on: ubuntu-latest
    if: ${{ contains(fromJSON('["refs/heads/main", "refs/heads/develop"]'), github.ref) }}
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  # Case 3: Step-level with explicit checks
  test_step_explicit:
    runs-on: ubuntu-latest
    steps:
      - name: Check actor
        if: ${{ github.actor == 'dependabot' || github.actor == 'renovate' }}
        run: echo "Bot detected"

  # Case 4: Using contains() for single substring (no spaces)
  test_single_substring:
    runs-on: ubuntu-latest
    steps:
      - name: Check if contains feature
        if: ${{ contains(github.ref, 'feature') }}
        run: echo "Feature branch"

  # Case 5: Using startsWith() for prefix matching
  test_starts_with:
    runs-on: ubuntu-latest
    if: ${{ startsWith(github.ref, 'refs/heads/feature/') }}
    steps:
      - run: echo "Feature branch"

  # Case 6: Using endsWith() for suffix matching
  test_ends_with:
    runs-on: ubuntu-latest
    if: ${{ endsWith(github.ref, '/main') }}
    steps:
      - run: echo "Main branch"

```
## Non-Compliant Code Examples
```yaml
name: Composite action with unsafe contains
description: Composite step uses contains() against a non-user-controllable context
runs:
  using: composite
  steps:
    - name: Check trigger
      if: ${{ contains('push pull_request', github.event_name) }}
      shell: bash
      run: echo "Trigger check"

```

```yaml
name: Unsound Contains Usage
on: pull_request

jobs:
  # Case 1: Contains with non-user-controllable context
  test_safe_context:
    runs-on: ubuntu-latest
    if: ${{ contains('push pull_request', github.event_name) }}
    steps:
      - run: echo "This is informational, not high severity"

```