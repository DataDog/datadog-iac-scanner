---
title: "Unpinned actions full length commit SHA"
group_id: "CICD / GitHub"
meta:
  name: "github/unpinned_actions_full_length_commit_sha"
  id: "555ab8f9-2001-455e-a077-f2d0f41e2fb9"
  display_name: "Unpinned actions full length commit SHA"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** `555ab8f9-2001-455e-a077-f2d0f41e2fb9`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)

### Description

Pinning an action to a full-length commit SHA is currently the only way to use it as an immutable release. This helps mitigate the risk of a bad actor introducing a backdoor, as doing so would require generating a SHA-1 collision for a valid Git object. When choosing a SHA, ensure it comes from the action's original repository and not a fork.

## Compliant Code Examples
```yaml
name: test-positive
on:
  pull_request:
    types: [opened, synchronize, edited, reopened]
    branches: 
      - master
jobs:
  test-positive:
    runs-on: ubuntu-latest
    steps:
    - name: PR comment
      uses: thollander/actions-comment-pull-request@b07c7f86be67002023e6cb13f57df3f21cdd3411
      with:
        comment_tag: title_check
        mode: recreate
        create_if_not_exists: true
```

```yaml
name: test-positive
on:
  pull_request:
    types: [opened, synchronize, edited, reopened]
    branches:
      - master
jobs:
  test-positive:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout Code
      uses: actions/checkout@v4
      with:
        persist-credentials: false

```

```yaml
name: test-negative3
on:
  pull_request:
    types: [opened, synchronize, edited, reopened]
    branches:
      - master
jobs:
  test-negative3:
    runs-on: ubuntu-latest
    steps:
    - name: Local action
      uses: ./test.yml

```
## Non-Compliant Code Examples
```yaml
name: test-positive
on:
  pull_request:
    types: [opened, synchronize, edited, reopened]
    branches: 
      - master
jobs:
  test-positive:
    runs-on: ubuntu-latest
    steps:
    - name: PR comment
      uses: thollander/actions-comment-pull-request@v2
      with:
        comment_tag: title_check
        mode: recreate
        create_if_not_exists: true
```