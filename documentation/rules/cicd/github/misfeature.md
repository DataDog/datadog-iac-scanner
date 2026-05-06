---
title: "Misfeature"
group_id: "CICD / GitHub"
meta:
  name: "github/misfeature"
  id: "a4b5c6d7-e8f9-40a1-b2c3-d4e5f6a7b8c9"
  display_name: "Misfeature"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** {{< copyable-code >}}a4b5c6d7-e8f9-40a1-b2c3-d4e5f6a7b8c9{{< /copyable-code >}}

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)

### Description

Certain GitHub Actions features create brittle or hard-to-audit workflows that increase the risk of inconsistent builds, unexpected runtime behavior, and missed detection of unsafe commands.

The `pip-install` input to `actions/setup-python` installs packages into a global (user or system) Python environment rather than an isolated virtual environment. This can lead to inconsistent dependency resolution and unexpected side effects across different runners and Python versions. This rule flags workflow steps that use `uses: actions/setup-python` with a `with` mapping that contains `pip-install`. Avoid that input and instead create and use a virtual environment, such as `python -m venv` and activating it, before installing packages.

Using `shell: cmd` or `cmd.exe` for `run` steps hampers static analysis because Windows `CMD` has no formal grammar and multiple line-continuation behaviors, which can hide unsafe commands or make auditing unreliable. This rule flags steps with `shell: cmd`/`cmd.exe` and will also flag other non‑well‑known shells as auditor findings. Prefer well-known shells like `pwsh` or `bash` when possible.

Secure configuration examples:

```yaml
- name: Setup Python and use a virtual environment
  uses: actions/setup-python@v4
  with:
    python-version: '3.11'

- name: Create and activate venv, then install
  run: |
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
```

```yaml
- name: Run script with PowerShell on Windows
  shell: pwsh
  run: |
    Write-Host "Performing build steps..."
    ./build.ps1
```

## Compliant Code Examples
```yaml
name: Proper Features Usage
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python properly
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install with venv
        shell: bash
        run: |
          python -m venv venv
          source venv/bin/activate
          pip install -r requirements.txt

      - name: PowerShell on Windows
        shell: pwsh
        run: Write-Host "Using PowerShell"

```
## Non-Compliant Code Examples
```yaml
name: Composite action with misfeatures
description: Composite action that uses pip-install and CMD shell
runs:
  using: composite
  steps:
    - name: Setup Python with pip-install
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'
        pip-install: 'pytest requests'
    - name: CMD shell usage
      shell: cmd
      run: echo "Using deprecated CMD shell"

```

```yaml
name: Misfeature Usage
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python with pip-install
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          pip-install: 'pytest requests'

      - name: CMD shell usage
        shell: cmd
        run: echo "Using deprecated CMD shell"

```