---
title: "Unsecured commands"
group_id: "CICD / GitHub"
meta:
  name: "github/unsecured_commands"
  id: "60fd272d-15f4-4d8f-afe4-77d9c6cc0453"
  display_name: "Unsecured commands"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `60fd272d-15f4-4d8f-afe4-77d9c6cc0453`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://0xn3va.gitbook.io/cheat-sheets/ci-cd/github/actions#misuse-of-the-events-related-to-incoming-prs)

### Description

The deprecated `set-env` and `add-path` commands can still be explicitly enabled by setting the `ACTIONS_ALLOW_UNSECURE_COMMANDS` environment variable to true. Depending on how this variable is used, an attacker could potentially modify the system path to run unintended commands, which may lead to arbitrary code execution.

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
## Non-Compliant Code Examples
```yaml
name: Vulnerable workflow

on:
  pull_request_target


jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
    steps:
      # 2. Print github context
      - run: |
          print("""${{ toJSON(github) }}""")
        shell: python
      - name: Create new PR deployment
        uses: actions/github-script@v5
        with:
          # 3. Create deployment
          script: |
            return await github.rest.repos.createDeployment({
                ...context.repo,
                ref: context.payload.pull_request.head.sha,
                auto_merge: false,
                required_contexts: [],
                environment: "${{ env.ENVIRONMENT_NAME }}",
                transient_environment: false,
                production_environment: false,
            });
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

```yaml
name: Vulnerable workflow

on:
  pull_request_target

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      # 2. Print github context
      - run: |
          print("""${{ toJSON(github) }}""")
        shell: python
      - name: Create new PR deployment
        env:
          ACTIONS_ALLOW_UNSECURE_COMMANDS: true
        uses: actions/github-script@v5
        with:
          # 3. Create deployment
          script: |
            return await github.rest.repos.createDeployment({
                ...context.repo,
                ref: context.payload.pull_request.head.sha,
                auto_merge: false,
                required_contexts: [],
                environment: "${{ env.ENVIRONMENT_NAME }}",
                transient_environment: false,
                production_environment: false,
            });
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

```yaml
name: Vulnerable workflow

on:
  pull_request_target

env:
  # 1. Enable unsecure commands
  ACTIONS_ALLOW_UNSECURE_COMMANDS: true
  ENVIRONMENT_NAME: prod

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      # 2. Print github context
      - run: |
          print("""${{ toJSON(github) }}""")
        shell: python
      - name: Create new PR deployment
        uses: actions/github-script@v5
        with:
          # 3. Create deployment
          script: |
            return await github.rest.repos.createDeployment({
                ...context.repo,
                ref: context.payload.pull_request.head.sha,
                auto_merge: false,
                required_contexts: [],
                environment: "${{ env.ENVIRONMENT_NAME }}",
                transient_environment: false,
                production_environment: false,
            });
          github-token: ${{ secrets.GITHUB_TOKEN }}
```