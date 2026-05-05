---
title: "Cache poisoning"
group_id: "CICD / GitHub"
meta:
  name: "github/cache_poisoning"
  id: "cicd-common-cache-poisoning"
  display_name: "Cache poisoning"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Supply-Chain"
---
## Metadata

**Id:** `cicd-common-cache-poisoning`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://adnanthekhan.com/2024/05/06/breaking-rulesets-github-artifact-poisoning/)

### Description

Publishing workflows that build and publish runtime artifacts must not write to dependency caches. A poisoned cache can introduce malicious dependencies into packages, releases, or container images, leading to supply-chain compromise. For example, using writable caches exposed to pull request workflows. 

This rule inspects GitHub Actions workflow job steps. The `uses` key identifies cache-aware actions such as `actions/cache`, `actions/setup-go`, `actions/setup-node`, `actions/setup-python`, `Swatinem/rust-cache`, and others. It also identifies `with` mappings containing cache-related controls.

When a job is triggered by release events or contains well-known publisher steps, `cache-write` flags must be disabled. For example, set `lookup-only: true` for `actions/cache` and `cache: false` for boolean `cache` controls. Steps missing a disabling flag, explicitly enabling caching, or relying on an action's default caching behavior will be flagged. Some actions use string-valued fields to control caching, and non-configurable actions cannot be automatically fixed.

Secure examples:

```yaml
- uses: actions/cache@v4
  with:
    path: |
      ~/.cargo/registry
      ~/.cargo/git
    key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
    lookup-only: true
```

```yaml
- uses: actions/setup-go@v4
  with:
    go-version: '1.21'
    cache: false
```

## Compliant Code Examples
```yaml
# Test case 1: Cache properly disabled with empty string in release
name: Secure Publishing Workflow - Node
on:
  release:
    types: [published]

jobs:
  publish-node:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        name: secure-node
        with:
          node-version: '18'
          package-manager-cache: false

      - run: npm ci

      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}

---
# Test case 2: Cache disabled in Python publishing workflow
name: Secure Python Publishing
on:
  push:
    tags:
      - 'v*'

jobs:
  publish-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        name: secure-python
        with:
          python-version: '3.11'

      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_API_TOKEN }}

---
# Test case 3: actions/cache with lookup-only in publishing workflow
name: Secure Release with Lookup-Only Cache
on:
  release:

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/cache@v4
        name: secure-cache
        with:
          path: ~/.npm
          key: ${{ runner.os }}-npm-${{ hashFiles('**/package-lock.json') }}
          lookup-only: true

      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: user/app:latest

---
# Test case 4: Rust cache properly disabled with lookup-only
name: Secure Rust Publishing
on:
  release:
    types: [created]

jobs:
  publish-rust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: Swatinem/rust-cache@v2
        name: secure-rust
        with:
          lookup-only: true

      - run: cargo publish
        env:
          CARGO_REGISTRY_TOKEN: ${{ secrets.CRATES_IO_TOKEN }}

---
# Test case 5: Cache enabled in non-publishing workflow (safe)
name: Safe Development Build
on:
  pull_request:
  push:
    branches:
      - main
      - develop

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        name: safe-pr-cache
        with:
          node-version: '18'
          cache: 'npm'

      - run: npm ci
      - run: npm test

---
# Test case 6: Java without cache in release
name: Secure Java Release
on:
  push:
    branches:
      - 'releases/**'

jobs:
  publish-java:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-java@v4
        name: secure-java
        with:
          distribution: 'temurin'
          java-version: '17'

      - run: mvn deploy

---
# Test case 7: Go with cache disabled (boolean false)
name: Secure Go Publishing
on:
  release:

jobs:
  publish-go:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        name: secure-go
        with:
          go-version: '1.21'
          cache: false

      - uses: goreleaser/goreleaser-action@v5
        with:
          version: latest
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

---
# Test case 8: DotNet without cache in Azure deployment
name: Secure DotNet Azure Deploy
on:
  push:
    tags:
      - 'v*'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-dotnet@v4
        name: secure-dotnet
        with:
          dotnet-version: '8.0.x'
          cache: false

      - uses: Azure/functions-action@v1
        with:
          app-name: 'my-function-app'

---
# Test case 9: Ruby without bundler-cache
name: Secure Ruby Gem Release
on:
  release:
    types: [published]

jobs:
  publish-gem:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: ruby/setup-ruby@v1
        name: secure-ruby
        with:
          ruby-version: '3.2'
          bundler-cache: false

      - uses: rubygems/release-gem@v1

---
# Test case 10: Gradle with cache-disabled
name: Secure Gradle Release
on:
  push:
    tags:
      - 'v*'

jobs:
  publish-gradle:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: gradle/actions/setup-gradle@v3
        name: secure-gradle
        with:
          cache-disabled: true

      - run: ./gradlew publish

---
# Test case 11: Docker buildx without cache
name: Secure Docker Build
on:
  release:

jobs:
  docker-publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: docker/setup-buildx-action@v3
        name: secure-buildx
        with:
          cache-binary: false

      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: myimage:latest

---
# Test case 12: Composer with ignore-cache
name: Secure Composer Release
on:
  release:

jobs:
  publish-php:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: ramsey/composer-install@v3
        name: secure-composer
        with:
          ignore-cache: 'yes'

      - run: composer publish

---
# Test case 13: Non-publishing trigger with main branch (safe)
name: Safe CI Build
on:
  push:
    branches:
      - main

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        name: safe-main-cache
        with:
          python-version: '3.11'
          cache: 'pip'

      - run: pip install -r requirements.txt
      - run: pytest

---
# Test case 14: UV cache disabled in release
name: Secure UV Release
on:
  release:

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v3
        name: secure-uv
        with:
          enable-cache: false

      - run: uv publish

---
# Test case 15: mise-action with cache disabled
name: Secure Mise Release
on:
  push:
    tags:
      - 'v*'

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: jdx/mise-action@v2
        name: secure-mise
        with:
          cache: false

      - uses: softprops/action-gh-release@v1
        with:
          files: dist/*

---
# Test case 16: GraalVM without cache
name: Secure GraalVM Release
on:
  release:

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: graalvm/setup-graalvm@v1
        name: secure-graalvm
        with:
          java-version: '21'
          distribution: 'graalvm'

      - run: ./gradlew publish

---
# Test case 17: Bun with no-cache enabled
name: Secure Bun Release
on:
  push:
    tags:
      - 'v*'

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: oven-sh/setup-bun@v2
        name: secure-bun
        with:
          no-cache: true

      - run: bun publish

---
# Test case 18: Cache in non-release branch (safe)
name: Safe Feature Branch
on:
  push:
    branches:
      - 'feature/*'

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: Mozilla-Actions/sccache-action@v0.0.5
        name: safe-sccache

      - run: cargo test

---
# Test case 19: actions/cache without lookup-only in non-publishing workflow
name: Secure Release with Lookup-Only Cache
on:
  push:

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/cache@v4
        name: secure-cache
        with:
          path: ~/.npm
          key: ${{ runner.os }}-npm-${{ hashFiles('**/package-lock.json') }}

      - uses: docker/build-push-action@v5
        with:
          push: false
          tags: user/app:latest

```
## Non-Compliant Code Examples
```yaml
# Test case 1: Opt-in string action with release trigger
name: Vulnerable Publishing Workflow - Release Trigger
on:
  release:
    types: [published]

jobs:
  publish-node:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        name: vulnerable-setup-node
        with:
          node-version: '18'
          cache: 'npm'

      - run: npm ci

      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}

---
# Test case 2: Opt-in action with boolean
name: Vulnerable Python Publishing
on:
  push:
    tags:
      - 'v*'

jobs:
  publish-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        name: vulnerable-setup-python
        with:
          python-version: '3.11'
          cache: 'pip'

      - run: pip install build

      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_API_TOKEN }}

---
# Test case 3: actions/cache with push to release branch
name: Vulnerable Release Branch Cache
on:
  push:
    branches:
      - 'release/*'

jobs:
  build-and-publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/cache@v4
        name: vulnerable-cache
        with:
          path: ~/.npm
          key: ${{ runner.os }}-npm-${{ hashFiles('**/package-lock.json') }}

      - run: npm ci

      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: user/app:latest

---
# Test case 4: Opt-out action (cache enabled by default)
name: Vulnerable Rust Cache
on:
  release:
    types: [created]

jobs:
  publish-rust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: Swatinem/rust-cache@v2
        name: vulnerable-rust-cache

      - run: cargo publish
        env:
          CARGO_REGISTRY_TOKEN: ${{ secrets.CRATES_IO_TOKEN }}

---
# Test case 5: Not configurable action (always caches)
name: Vulnerable sccache
on:
  push:
    tags:
      - 'release-*'

jobs:
  publish-with-sccache:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: Mozilla-Actions/sccache-action@v0.0.5
        name: vulnerable-sccache

      - uses: softprops/action-gh-release@v1
        with:
          files: dist/*
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

---
# Test case 6: Java setup with cache
name: Vulnerable Java Release
on:
  push:
    branches:
      - 'releases/**'

jobs:
  publish-java:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-java@v4
        name: vulnerable-setup-java
        with:
          distribution: 'temurin'
          java-version: '17'
          cache: 'maven'

      - run: mvn deploy

---
# Test case 7: Multiple cache-aware actions in publisher job
name: Vulnerable Multi-Cache Job
on:
  release:

jobs:
  publish-multi:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        name: vulnerable-setup-go
        with:
          go-version: '1.21'
          cache: true

      - uses: actions/cache@v4
        name: vulnerable-cache-multi
        with:
          path: ~/go/pkg/mod
          key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}

      - uses: goreleaser/goreleaser-action@v5
        with:
          version: latest
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

---
# Test case 8: Opt-in with explicit true
name: Vulnerable DotNet Cache
on:
  push:
    tags:
      - 'v[0-9]+.*'

jobs:
  publish-dotnet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-dotnet@v4
        name: vulnerable-setup-dotnet
        with:
          dotnet-version: '8.0.x'
          cache: true

      - uses: Azure/functions-action@v1
        with:
          app-name: 'my-function-app'

---
# Test case 9: Ruby bundler cache
name: Vulnerable Ruby Gem Release
on:
  release:
    types: [published]

jobs:
  publish-gem:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: ruby/setup-ruby@v1
        name: vulnerable-ruby-cache
        with:
          ruby-version: '3.2'
          bundler-cache: true

      - uses: rubygems/release-gem@v1

---
# Test case 10: Gradle with cache-disabled set to false
name: Vulnerable Gradle Build
on:
  push:
    branches:
      - 'release-*'

jobs:
  publish-gradle:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: gradle/actions/setup-gradle@v3
        name: vulnerable-gradle

      - run: ./gradlew publish

---
# Test case 11: Docker buildx with cache
name: Vulnerable Docker Build
on:
  release:

jobs:
  docker-publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: docker/setup-buildx-action@v3
        name: vulnerable-buildx
        with:
          cache-binary: true

      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: myimage:latest

---
# Test case 12: Multiple publisher actions indicating publishing
name: Vulnerable Cloud Deploy
on:
  push:
    branches:
      - main

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        name: vulnerable-node-cloud-deploy
        with:
          node-version: '20'
          cache: 'npm'
          package-manager-cache: true

      - uses: google-github-actions/deploy-cloudrun@v2
        with:
          service: my-service

---
# Test case 13: Opt-out string action
name: Vulnerable Composer Cache
on:
  release:

jobs:
  publish-php:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: ramsey/composer-install@v3
        name: vulnerable-composer

      - run: composer publish

```