---
title: "Script block injection"
group_id: "CICD / GitHub"
meta:
  name: "github/script_block_injection"
  id: "cicd-github-script-block-injection"
  display_name: "Script block injection"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}cicd-github-script-block-injection{{< /copyable-code >}}

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://securitylab.github.com/research/github-actions-untrusted-input/)

### Description

GitHub Actions steps that run arbitrary JavaScript via actions/github-script must not incorporate untrusted event fields into their script blocks because attackers can inject content that leads to code injection or unauthorized API calls and potentially exfiltrate secrets. Check workflow steps where `uses` starts with `actions/github-script` and ensure the `with.script` value does not reference user-controlled GitHub context properties such as `github.event.pull_request.*`, `github.event.issue.*`, `github.event.comment.*`, `github.event.discussion.*`, or `github.event.workflow_run.*`; steps whose script contains these patterns will be flagged. If processing event data is required, validate and sanitize inputs, restrict workflow permissions (avoid `pull_request_target` when running untrusted content), or perform parsing in a hardened action or external service with least privilege. For the `pull_request` trigger, the vulnerable fields are much more significant when the change comes from a fork.

Secure example that avoids using event fields:

```yaml
- name: Safe script
  uses: actions/github-script@v6
  with:
    script: |
      core.info('No user-controlled event data used.')
```

## Compliant Code Examples
```yaml
name: test-script-run

on:
  issues:
    types: [opened]

jobs:
  script-run:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run script
        uses: actions/github-script@latest
        with:
          script: |
            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: 'Thanks for reporting!'
            })

            return true;

```

```yaml
name: test-script-run

on:
  workflow_run:
    types: [opened]

jobs:
  script-run:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run script
        uses: actions/github-script@latest
        with:
          script: |
            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: 'Thanks for reporting!'
            })

            return true;

```

```yaml
name: test-script-run

on:
  author:
    types: [opened]

jobs:
  script-run:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run script
        uses: actions/github-script@latest
        with:
          script: |
            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: 'Thanks for reporting!'
            })

            return true;

```
## Non-Compliant Code Examples
```yaml
name: test-script-run

on:
  pull_request_target:
    types: [opened]

jobs:
  script-run:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run script
        uses: actions/github-script@latest
        with:
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('/tmp/${{ github.event.pull_request.title }}.txt', {encoding: 'utf8'});

            await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: 'Thanks for reporting!'
            })

            return true;

```

```yaml
name: Composite action with github-script using inputs
description: Composite action that runs github-script with attacker-controlled composite inputs
inputs:
  message:
    description: Message provided by the caller
    required: true
runs:
  using: composite
  steps:
    - name: Run script
      uses: actions/github-script@v7
      with:
        script: |
          const body = `${{ inputs.message }}`;
          core.info(body);

```

```yaml
name: Composite action with github-script
description: Composite action that runs github-script with untrusted issue body
runs:
  using: composite
  steps:
    - name: Run script
      uses: actions/github-script@v7
      with:
        script: |
          const body = `${{ github.event.issue.body }}`;
          await github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: 'Thanks for reporting!'
          })

```