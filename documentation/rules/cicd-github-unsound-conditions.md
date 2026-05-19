---
title: "Unsound condition"
group_id: "CICD / GitHub"
meta:
  name: ""github/unsound_conditions""
  id: "cicd-github-unsound-conditions"
  display_name: "Unsound condition"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Build Process"
---
## Metadata

**Id:** {{< copyable-code >}}cicd-github-unsound-conditions{{< /copyable-code >}}

**Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idif)

### Description

Conditions that mix fenced GitHub Actions expressions (`${{ ... }}`) with YAML multiline block scalars (`|` or `>`) can evaluate incorrectly. The block scalar often adds trailing newlines, turning the expanded value into a non-empty string that GitHub Actions treats as truthy. This can cause conditions that should be false to always pass, allowing jobs or steps to run unintentionally. This check inspects the `if` property on jobs, steps, and reusable workflow calls. It flags cases where the `if` value contains a fenced expression and the overall scalar includes extra leading or trailing content, indicating that block style added whitespace or newlines. Remediate by using stripped block scalar styles (`|-` or `>-`) to remove trailing newlines, or by using a plain inline expression such as `if: ${{ ... }}`, so the fenced expression is evaluated as an expression rather than as a non-empty string.

Secure examples:

```yaml
# Stripped literal block scalar removes trailing newline
if: |-
  ${{ github.event_name == 'push' }}
```

```yaml
# Inline fenced expression (single line)
if: ${{ github.event_name == 'push' }}
```

## Compliant Code Examples
```yaml
name: Sound Conditions
on: push

jobs:
  # Case 1: Job-level with plain scalar (no block style)
  job_with_sound_condition:
    runs-on: ubuntu-latest
    if: ${{ github.event_name == 'pull_request' }}
    steps:
      - run: echo "This is sound"

  # Case 2: Properly fenced conditions
  test_sound_conditions:
    runs-on: ubuntu-latest
    steps:
      - name: Plain scalar condition
        if: ${{ github.event_name == 'push' }}
        run: echo "This condition is sound"

      # Case 3: Stripped literal block scalar (|- removes trailing newlines)
      - name: Stripped literal block scalar
        if: |-
          ${{ github.ref == 'refs/heads/main' }}
        run: echo "This is also sound"

      # Case 4: Stripped folded block scalar (>- removes trailing newlines)
      - name: Stripped folded block scalar
        if: >-
          ${{ github.actor != 'dependabot' }}
        run: echo "This is sound too"

      # Case 5: Bare expression without quotes (GitHub Actions evaluates this correctly)
      - name: Bare expression
        if: github.event_name == 'push'
        run: echo "No fencing, sound"

      # Case 6: Complex condition without excessive whitespace
      - name: Complex condition
        if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}
        run: echo "Complex but sound"

```
## Non-Compliant Code Examples
```yaml
name: Composite action with unsound conditions
description: Composite action whose step conditions use YAML block scalars
runs:
  using: composite
  steps:
    - name: Unsound literal block
      if: |
        ${{ inputs.deploy == 'true' }}
      shell: bash
      run: echo "This will always run!"

```

```yaml
name: Unsound Conditions
on: push

jobs:
  # Case 1: Job-level condition with literal block scalar
  job_with_unsound_condition:
    runs-on: ubuntu-latest
    if: |
      ${{ github.event_name == 'pull_request' }}
    steps:
      - run: echo "This will always run!"

  # Case 2: Step-level literal block scalar
  test_literal_block:
    runs-on: ubuntu-latest
    steps:
      - name: Unsound literal block
        if: |
          ${{ github.event_name == 'pull_request' }}
        run: echo "This will always run!"

      # Case 3: Folded block scalar
      - name: Unsound folded block
        if: >
          ${{ false }}
        run: echo "This will also always run!"

      # Case 4: Multiple spaces (excessive whitespace)
      - name: Excessive leading spaces
        if: "  ${{ github.ref == 'refs/heads/main' }}"
        run: echo "Has leading spaces"

      # Case 5: Tabs
      - name: Tab character
        if: "	${{ true }}"
        run: echo "Has tab character"

      # Case 6: Trailing spaces
      - name: Excessive trailing spaces
        if: "${{ github.actor == 'dependabot' }}  "
        run: echo "Has trailing spaces"

      # Case 7: Single space
      - name: Single space padding
        if: " ${{ true }} "
        run: echo "Single space is not fine"

```