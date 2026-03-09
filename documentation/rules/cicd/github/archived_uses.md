---
title: "Archived uses"
group_id: "CICD / GitHub"
meta:
  name: "github/archived_uses"
  id: "b2c3d4e5-f6a7-48b9-c0d1-e2f3a4b5c6d7"
  display_name: "Archived uses"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Supply Chain"
---
## Metadata

**Id:** `b2c3d4e5-f6a7-48b9-c0d1-e2f3a4b5c6d7`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Supply Chain

#### Learn More

 - [Provider Reference](https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories)

### Description

Using actions or reusable workflows from archived repositories is risky because archived repositories no longer receive security fixes and may be deleted or transferred, which can leave workflows vulnerable and cause builds to break. This rule checks the `uses` property on workflow steps — including regular steps, composite action steps, and reusable-workflow call jobs — and flags any `uses` that references an archived repository, matching owner and repo case-insensitively. Replace archived actions with actively maintained alternatives, fork and maintain the action under your control, or vendor the code into your own repository; pinning to a commit does not restore ongoing security maintenance.

Secure examples:

```yaml
- name: Checkout
  uses: actions/checkout@v4

- name: My maintained forked action
  uses: my-org/some-action@v1
```

## Compliant Code Examples
```yaml
name: Valid Workflow with Active Actions
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4

```
## Non-Compliant Code Examples
```yaml
name: Workflow with Archived Action
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Use archived action
        uses: someowner/archived-action@v1

```