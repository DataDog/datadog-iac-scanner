---
title: "Use trusted publishing for authentication"
group_id: "CICD / GitHub"
meta:
  name: "github/use_trusted_publishing"
  id: "f9a0b1c2-d3e4-45f6-a7b8-c9d0e1f2a3b4"
  display_name: "Use trusted publishing for authentication"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** {{< copyable-code >}}f9a0b1c2-d3e4-45f6-a7b8-c9d0e1f2a3b4{{< /copyable-code >}}

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.pypi.org/trusted-publishers/)

### Description

Workflows that publish packages should use Trusted Publishing (GitHub OIDC) instead of embedding long-lived tokens or other manually configured credentials. Manual credentials increase the risk of leakage, reuse across projects, and supply-chain compromise. This rule flags publishing steps that supply explicit credentials or indicate manual token use, and `run` steps that invoke publish commands without OIDC `id-token` permissions.

For `uses` steps, known publishing actions are flagged — such as `pypa/gh-action-pypi-publish`, `rubygems/release-gem`, `rubygems/configure-rubygems-credentials`, and `actions/setup-node` — when `with` contains keys like `password`, `api-token`, or `always-auth` set to `true`, or when `with.setup-trusted-publisher` is not set to `true`. The rule also checks `with.repository-url` / `with.repository_url` and `with.registry-url` against known trusted indices to determine intent.

For `run` steps, commands that match publishing operations are flagged — such as `cargo publish`, `twine upload`, `npm publish`, `gem push`, and `dotnet nuget push` — when the parent job does not grant the OIDC `id-token` permission (e.g., `permissions.id-token: write`). Resources missing the appropriate OIDC permissions or containing the listed insecure `with` values will be flagged. Remediate by removing hardcoded tokens/credentials and configuring the job/actions to rely on `id-token` or the action's Trusted Publishing option. 

Secure example:

```yaml
jobs:
  publish:
    permissions:
      id-token: write
    steps:
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@v1
        with:
          repository-url: https://upload.pypi.org/legacy/
```

## Compliant Code Examples
```yaml
name: Trusted Publishing Test - Negative Cases
on:
  push:
    branches: [main]

jobs:
  pypi-trusted-publishing:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4

      - name: Publish to PyPI with Trusted Publishing
        uses: pypa/gh-action-pypi-publish@release/v1
        # No password - uses OIDC token

  rubygems-trusted-publishing:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4

      - name: Release gem with trusted publishing
        uses: rubygems/release-gem@v1
        with:
          setup-trusted-publisher: true

  npm-trusted-publishing:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20
          registry-url: https://registry.npmjs.org
          # No always-auth, will use provenance

  cargo-with-token:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4

      - name: Publish to crates.io with token permission
        run: cargo publish

  dry-run-commands:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Dry run cargo publish
        run: cargo publish --dry-run

      - name: Dry run npm publish
        run: npm publish --dry-run

      - name: Dry run poetry publish
        run: poetry publish --dry-run

  non-publishing-commands:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build with cargo
        run: cargo build --release

      - name: Run tests
        run: npm test

      - name: Install with gem
        run: gem install bundler

  different-registries:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Private registry, not npmjs.org
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          registry-url: https://npm.pkg.github.com
          always-auth: true

  rubygems-private-server:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Private gem server, not rubygems.org
      - name: Configure private gem server
        uses: rubygems/configure-rubygems-credentials@main
        with:
          api-token: ${{ secrets.PRIVATE_GEM_TOKEN }}
          gem-server: https://private-gems.example.com

  workflow-level-permissions:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Publish with workflow-level token
        run: twine upload dist/*

permissions:
  id-token: write

```
## Non-Compliant Code Examples
```yaml
name: Trusted Publishing Test - Positive Cases
on:
  push:
    branches: [main]

jobs:
  pypi-manual-password:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Publish to PyPI with password
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_API_TOKEN }}

  rubygems-no-trusted:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Release gem without trusted publishing
        uses: rubygems/release-gem@v1

  rubygems-disabled-trusted:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Release gem with trusted publishing disabled
        uses: rubygems/release-gem@v1
        with:
          setup-trusted-publisher: false

  rubygems-manual-token:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure RubyGems with manual token
        uses: rubygems/configure-rubygems-credentials@main
        with:
          api-token: ${{ secrets.RUBYGEMS_API_KEY }}
          gem-server: https://rubygems.org

  npm-manual-auth:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20
          registry-url: https://registry.npmjs.org
          always-auth: true

  cargo-publish-no-token:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Publish to crates.io
        run: cargo publish

  twine-upload-no-token:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Publish to PyPI with twine
        run: twine upload dist/*

  npm-publish-no-token:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Publish to npm
        run: npm publish

  gem-push-no-token:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Push gem
        run: gem push mygem-1.0.0.gem

  poetry-publish-no-token:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Publish with poetry
        run: poetry publish

  yarn-publish-no-token:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Publish with yarn
        run: yarn publish

  pnpm-publish-no-token:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Publish with pnpm
        run: pnpm publish

  nuget-push-no-token:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Push to NuGet
        run: nuget push MyPackage.nupkg

  dotnet-nuget-push:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Push with dotnet
        run: dotnet nuget push MyPackage.nupkg

  uv-publish-no-token:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Publish with uv
        run: uv publish

  python-m-twine:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Publish with python -m twine
        run: python -m twine upload dist/*

```