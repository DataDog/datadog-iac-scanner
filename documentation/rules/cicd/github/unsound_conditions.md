---
title: "Unsound condition"
group_id: "CICD / GitHub"
meta:
  name: "github/unsound_conditions"
  id: "d4e5f6a7-b8c9-40d1-e2f3-a4b5c6d7e8f9"
  display_name: "Unsound condition"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Build Process"
---
## Metadata

**Id:** `d4e5f6a7-b8c9-40d1-e2f3-a4b5c6d7e8f9`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idif)

### Description

Conditions that mix fenced GitHub Actions expressions, written `${{ ... }}`, with YAML multiline block scalars, such as`|` or `>`, can evaluate incorrectly because the block scalar often adds trailing newlines, turning the expanded value into a non-empty string that GitHub Actions treats as truthy; this can cause statements that should be false to always pass and allow jobs or steps to run unintentionally. This check inspects the `if` property on jobs, steps, and reusable workflow calls and flags cases where the `if` value contains a fenced expression and the overall scalar includes extra leading/trailing content, which indicates a block style added whitespace/newlines. Remediate by using stripped block scalar styles (`|-` or `>-`) to remove trailing newlines or by using a plain inline expression, such as `if: ${{ ... }}`, so the fenced expression is evaluated as an expression rather than as a non-empty string.

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
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Properly fenced condition
        if: ${{ github.event_name == 'push' }}
        run: echo "This condition is sound"

      - name: Stripped block scalar
        if: |-
          ${{ github.ref == 'refs/heads/main' }}
        run: echo "This is also sound"

```
## Non-Compliant Code Examples
```yaml
name: Unsound Conditions
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Unsound literal block
        if: |
          ${{ github.event_name == 'pull_request' }}
        run: echo "This will always run!"

      - name: Unsound folded block
        if: >
          ${{ false }}
        run: echo "This will also always run!"

```