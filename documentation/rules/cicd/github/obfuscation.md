---
title: "Obfuscation"
group_id: "CICD / GitHub"
meta:
  name: "github/obfuscation"
  id: "cicd-common-obfuscation"
  display_name: "Obfuscation"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `cicd-common-obfuscation`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsuses)

### Description

Obfuscated GitHub Actions usage (for example, weird `uses:` paths or needlessly complex/fenced expressions) makes workflows harder to audit and can hide malicious or unintended behavior.

For repository action references, the step `uses` property must not contain empty path components, `.` or `..`. It should be normalized to the concrete form `owner/repo[/path]@ref` so pattern-matching and provenance analysis work reliably.

For expressions anywhere routable text is allowed (such as step inputs/outputs and workflow fields), constant-reducible expressions should be replaced by their evaluated constant, and computed index expressions should be avoided. When replacing an entire fenced expression written `${{ ... }}`, the fix must remove the fencing to preserve semantics. Fixes for reducible sub-expressions should target only the subfragment.

This rule flags step `uses` values with empty components or `.`/`..`, fenced expressions that can be constant-reduced, and computed index expressions. Automated fixes normalize `uses` paths and either replace full expressions with their evaluated value or rewrite only the reducible subexpression when possible.

Secure examples:

```yaml
# normalized repository action reference
- uses: actions/checkout@v4
```

```yaml
# replace constant-fenced expression with its evaluated value
outputs:
  iac/terraform/attribution.tfm--release_created: steps.release.outputs.iac/terraform/attribution.tfm--release_created
```

## Compliant Code Examples
```yaml
name: Valid Uses Paths
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      # Standard action reference
      - uses: actions/checkout@v4

      # With subpath
      - uses: github/codeql-action/init@v2

      # Local action (starts with ./)
      - uses: ./path/to/action

      # Local action with subpath
      - uses: ./.github/actions/custom-action

      # Docker action
      - uses: docker://alpine:3.18

      # Action with valid nested path
      - uses: aws-actions/configure-aws-credentials/subaction@v4

      # Action with commit SHA
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd

```
## Non-Compliant Code Examples
```yaml
name: Composite action with obfuscated uses
description: Composite action that calls another action through an obfuscated path
runs:
  using: composite
  steps:
    - name: Use obfuscated action
      uses: actions/checkout/./@v4

```

```yaml
name: Obfuscated Uses Paths
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      # Empty components (multiple slashes)
      - uses: actions/checkout////@v4

      # Dot reference (current directory)
      - uses: github/codeql-action/./init@v2

      # Parent directory traversal
      - uses: actions/cache/save/../save@v4

      # Complex combination
      - uses: owner/repo/./path/../other//subdir@v1

      # Trailing slash with empty component
      - uses: actions/setup-node/@v4

```