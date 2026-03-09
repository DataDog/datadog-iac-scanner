---
title: "Superfluous actions"
group_id: "CICD / GitHub"
meta:
  name: "github/superfluous_actions"
  id: "b5c6d7e8-f9a0-41b2-c3d4-e5f6a7b8c9d0"
  display_name: "Superfluous actions"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `b5c6d7e8-f9a0-41b2-c3d4-e5f6a7b8c9d0`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/using-workflows/about-workflows)

### Description

Using third‑party GitHub Actions that duplicate functionality already provided by GitHub‑hosted runners increases supply‑chain and maintenance risk by introducing unnecessary external code, permissions, and update surface to your workflows. This rule checks workflow job steps and composite steps that declare a repository action via the `uses` property and flags known superfluous actions such as `ncipollo/release-action`, `softprops/action-gh-release`, `elgohr/Github-Release-Action`, `peter-evans/create-pull-request`, `peter-evans/create-or-update-comment`, `addnab/docker-run-action`, and `dtolnay/rust-toolchain`. Replace these with `run` script steps that call built‑in tools available on runners, such as `gh release`, `gh pr create`, `gh pr comment` / `gh issue comment`, `docker run`, or `rustup`/`cargo`, or use native container steps where appropriate. Any step with a `uses` value matching the listed repositories will be flagged.

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

      - name: Create release using gh CLI
        run: gh release create v1.0.0 --notes "Release notes"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Add comment using gh CLI
        run: gh pr comment ${{ github.event.pull_request.number }} --body "LGTM"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Run Docker container natively
        run: docker run --rm alpine:latest echo "Hello"

```
## Non-Compliant Code Examples
```yaml
name: Using Superfluous Actions
on: push

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Create release with action
        uses: ncipollo/release-action@v1
        with:
          tag: v1.0.0

      - name: Comment with action
        uses: peter-evans/create-or-update-comment@v4
        with:
          issue-number: 1
          body: LGTM

      - name: Run Docker with action
        uses: addnab/docker-run-action@v3
        with:
          image: alpine:latest
          run: echo "Hello"

```