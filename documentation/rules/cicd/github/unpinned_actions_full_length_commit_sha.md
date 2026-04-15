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

Steps that reference external GitHub Actions must be pinned to a full-length commit SHA to ensure the action's code is immutable and to reduce supply-chain tampering or unexpected behavior from upstream updates. The rule inspects the `uses` property in `step` attributes and requires the value to end with `@` followed by a 40-character lowercase hexadecimal commit SHA (pattern `@[a-f0-9]{40}`). Entries that do not match this pattern will be flagged. The check ignores local actions referenced with relative paths, starting with `./`, and references beginning with `actions/`. When pinning, use a commit SHA from the action's original repository so the pinned reference matches the intended source.

Secure example with a pinned action:

```yaml
- name: Build and push
  uses: docker/build-push-action@e3b0c44298fc1c149afbf4c8996fb92427ae41e4
```

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
name: test-negative4
on:
  pull_request:
    types: [opened, synchronize, edited, reopened]
    branches:
      - master
jobs:
  test-negative4:
    uses: my-org/shared-github-actions/.github/workflows/pr-comment-thollander.yml@b07c7f86be67002023e6cb13f57df3f21cdd3411

```

```yaml
name: test-negative4
on:
  pull_request:
    types: [opened, synchronize, edited, reopened]
    branches:
      - master
jobs:
  test-negative4:
    uses: ./.github/workflows/pr-comment-thollander.yml

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
    uses: my-org/shared-github-actions/.github/workflows/pr-comment-thollander.yml@v3

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
    - name: PR comment
      uses: thollander/actions-comment-pull-request@v2
      with:
        comment_tag: title_check
        mode: recreate
        create_if_not_exists: true
```