---
title: "Unsound contains with controllable input"
group_id: "CICD / GitHub"
meta:
  name: "github/unsound_contains_with_controllable_input"
  id: "cicd-github-unsound-contains-with-controllable-input"
  display_name: "Unsound contains with controllable input"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `cicd-github-unsound-contains-with-controllable-input`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/learn-github-actions/expressions#contains)

### Description

Using `contains()` with a string literal to validate a user controllable value is unsafe because `contains()` performs substring matching. Crafted values such as `refs/heads/mai` or `ain` can satisfy the check and bypass intended restrictions.

This is especially dangerous when the value being tested comes from user-controllable contexts such as `env.*`, `github.ref`, `github.ref_name`, `github.head_ref`, `github.base_ref`, `github.actor`, `github.sha`, `github.triggering_actor`, or `inputs.*`. An attacker can trigger unintended workflow paths, disclosures, or privileged actions.

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
description: Composite step if condition uses contains() against user-controllable input
runs:
  using: composite
  steps:
    - name: Check input
      if: ${{ contains('dev test prod', inputs.environment) }}
      shell: bash
      run: echo "Valid environment"

```

```yaml
name: Unsound Contains Usage
on: pull_request

jobs:
  # Case 1: Job-level condition with space-separated branches
  test_branches:
    runs-on: ubuntu-latest
    if: ${{ contains('refs/heads/main refs/heads/develop', github.ref) }}
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  # Case 2: Job-level condition with env variable
  test_env:
    runs-on: ubuntu-latest
    if: ${{ contains('production staging', env.ENVIRONMENT) }}
    steps:
      - run: echo "Deploying"

  # Case 3: Step-level condition with github.actor
  test_step_actor:
    runs-on: ubuntu-latest
    steps:
      - name: Check actor
        if: ${{ contains('dependabot renovate', github.actor) }}
        run: echo "Bot detected"

  # Case 4: Step-level with github.head_ref
  test_step_ref:
    runs-on: ubuntu-latest
    steps:
      - name: Check branch
        if: ${{ contains('feature/ bugfix/', github.head_ref) }}
        run: echo "Feature or bugfix"

  # Case 5: Using inputs (workflow_dispatch)
  test_inputs:
    runs-on: ubuntu-latest
    steps:
      - name: Check input
        if: ${{ contains('dev test prod', inputs.environment) }}
        run: echo "Valid environment"

  # Case 6: Single quotes with pipe delimiter
  test_pipe_delimiter:
    runs-on: ubuntu-latest
    if: ${{ contains('main|develop|staging', github.ref_name) }}
    steps:
      - run: echo "Branch check"

```