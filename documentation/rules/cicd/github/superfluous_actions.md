---
title: "Superfluous actions"
group_id: "CICD / GitHub"
meta:
  name: "github/superfluous_actions"
  id: "cicd-github-superfluous-actions"
  display_name: "Superfluous actions"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** {{< copyable-code >}}cicd-github-superfluous-actions{{< /copyable-code >}}

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/using-workflows/about-workflows)

### Description

Using third-party GitHub Actions that duplicate functionality already provided by GitHub-hosted runners increases supply-chain and maintenance risk. These actions introduce unnecessary external code, permissions, and update surface to your workflows.

This rule flags workflow job steps and composite steps that declare a repository action via the `uses` property. The following actions are flagged: `ncipollo/release-action`, `softprops/action-gh-release`, `elgohr/Github-Release-Action`, `peter-evans/create-pull-request`, `peter-evans/create-or-update-comment`, `addnab/docker-run-action`, and `dtolnay/rust-toolchain`.

Replace these with `run` script steps that call built-in tools available on runners. For example, use `gh release`, `gh pr create`, `gh pr comment` / `gh issue comment`, `docker run`, or `rustup`/`cargo`. You can also use native container steps where appropriate. Any step with a `uses` value matching the listed repositories will be flagged.

Secure replacement examples:

```yaml
- name: Create release
  run: gh release create v1.0.0 --title "v1.0.0"

- name: Post PR comment
  run: gh pr comment ${{ github.event.pull_request.number }} --body "Thanks for your contribution"

- name: Run container tool
  run: docker run --rm my-image:latest my-command

- name: Install Rust toolchain
  run: rustup toolchain install stable && cargo build --release
```

## Compliant Code Examples
```yaml
name: Using Built-in Tools
on: push

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Proper way to create releases
      - name: Create release using gh CLI
        run: gh release create v1.0.0 --notes "Release notes"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      # Proper way to add comments
      - name: Add comment using gh CLI
        run: gh pr comment ${{ github.event.pull_request.number }} --body "LGTM"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      # Proper way to run Docker containers
      - name: Run Docker container natively
        run: docker run --rm alpine:latest echo "Hello"

      # Proper way to upload release assets
      - name: Upload release assets using gh CLI
        run: gh release upload v1.0.0 dist/*
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      # Proper way to setup Rust
      - name: Setup Rust using rustup
        run: |
          curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
          rustup default stable
          cargo --version

      # Using non-superfluous actions is OK
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'

      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: ~/.npm
          key: ${{ runner.os }}-npm-${{ hashFiles('package-lock.json') }}

```
## Non-Compliant Code Examples
```yaml
name: Composite action using superfluous third-party action
description: Composite action that uses a superfluous third-party release action
runs:
  using: composite
  steps:
    - name: Create release
      uses: ncipollo/release-action@v1

```

```yaml
name: Using Superfluous Actions
on: push

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Use 'gh release' command instead
      - name: Create release with action
        uses: ncipollo/release-action@v1
        with:
          tag: v1.0.0

      # Use 'gh pr comment' or 'gh issue comment' instead
      - name: Comment with action
        uses: peter-evans/create-or-update-comment@v4
        with:
          issue-number: 1
          body: LGTM

      # Use 'docker run' command or container step instead
      - name: Run Docker with action
        uses: addnab/docker-run-action@v3
        with:
          image: alpine:latest
          run: echo "Hello"

      # Use 'gh release' command instead
      - name: Alternative release action
        uses: softprops/action-gh-release@v1
        with:
          files: dist/*

      # Use 'gh release' command instead
      - name: Another release action
        uses: elgohr/Github-Release-Action@v5
        with:
          title: Release v1.0.0

      # Use 'rustup' and/or 'cargo' commands instead
      - name: Setup Rust toolchain
        uses: dtolnay/rust-toolchain@stable

```