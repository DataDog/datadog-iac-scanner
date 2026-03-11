---
title: "Bot conditions"
group_id: "CICD / GitHub"
meta:
  name: "github/bot_conditions"
  id: "d4e5f6a7-b8c9-40d1-e2f3-a4b5c6d7e8f9"
  display_name: "Bot conditions"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `d4e5f6a7-b8c9-40d1-e2f3-a4b5c6d7e8f9`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)

### Description

GitHub Actions `if` conditions should not rely on top-level actor contexts like `github.actor`, `github.triggering_actor`, or their ID variants. Attacker-controlled usernames ending with `[bot]` or reused integration IDs can bypass actor checks and grant unintended access.

This rule inspects job and step-level `if` expressions and flags comparisons where spoofable contexts are checked against bot names or IDs, such as `github.actor == 'dependabot[bot]'` or `github.actor_id == '49699333'`. Instead, use event-specific user contexts so the actor is taken from the triggering event payload. For `pull_request` or `pull_request_target`, use `github.event.pull_request.user.login` / `github.event.pull_request.user.id`. For `issue_comment` and `discussion_comment`, use `github.event.comment.user.login` / `.id`. For `pull_request_review`, use `github.event.review.user.login` / `.id`. For `issues`, use `github.event.issue.user.login` / `.id`.

Known vulnerable bot IDs include `29110`, `49699333`, `27856297`, and `29139614`.

Secure example replacing `github.actor` with an event-specific context:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    if: github.event.pull_request.user.login == 'dependabot[bot]'
    steps:
      - name: Test Step
        if: github.event.pull_request.user.login == 'dependabot[bot]'
        run: echo "hello"
```

## Compliant Code Examples
```yaml
name: Secure Bot Check
on: pull_request

jobs:
  dependabot:
    runs-on: ubuntu-latest
    if: ${{ github.actor == 'dependabot[bot]' && github.actor_id == '49699333' }}
    steps:
      - name: Auto-approve
        run: gh pr review --approve
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

```
## Non-Compliant Code Examples
```yaml
name: Insecure Bot Check
on: pull_request

jobs:
  dependabot:
    runs-on: ubuntu-latest
    if: ${{ github.actor == 'dependabot[bot]' }}
    steps:
      - name: Auto-approve
        run: gh pr review --approve
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

```