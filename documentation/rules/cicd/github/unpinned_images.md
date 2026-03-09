---
title: "Unpinned images"
group_id: "CICD / GitHub"
meta:
  name: "github/unpinned_images"
  id: "c9d0e1f2-a3b4-45c6-d7e8-f9a0b1c2d3e4"
  display_name: "Unpinned images"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Supply Chain"
---
## Metadata

**Id:** `c9d0e1f2-a3b4-45c6-d7e8-f9a0b1c2d3e4`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Supply Chain

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idcontainer)

### Description

Container images used in GitHub Actions workflows must be pinned to immutable digests (SHA256) to ensure builds are repeatable and to prevent malicious or accidental replacement of an image via mutable tags. Check the job-level `container.image` and each `services.<name>.image` entry and require an image reference that includes a digest, which format follows `image@sha256:<hash>`. image references that lack a digest or that only use a tag, including `latest`, are considered unpinned. If an image is provided via a workflow expression, for example using `matrix` values, the expanded value must be a static digest; complex or non-static expressions will be flagged. To remediate, replace tag-only references with a digest-pinned reference, for example:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: node@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

    services:
      postgres:
        image: postgres@sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

## Compliant Code Examples
```yaml
name: Pinned Container Images
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: node@sha256:b4f0e0bdeb578043c518244e9f0f11f7e8b6d1a0f9f4e6e1e1f0a4f7c7e3c5a8
    services:
      postgres:
        image: postgres@sha256:c5e1c2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
    steps:
      - run: npm test

```
## Non-Compliant Code Examples
```yaml
name: Unpinned Container Images
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: node:18
    services:
      postgres:
        image: postgres:14
    steps:
      - run: npm test

```