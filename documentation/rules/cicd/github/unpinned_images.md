---
title: "Unpinned images"
group_id: "CICD / GitHub"
meta:
  name: "github/unpinned_images"
  id: "cicd-github-unpinned-images"
  display_name: "Unpinned images"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Supply-Chain"
---
## Metadata

**Id:** {{< copyable-code >}}cicd-github-unpinned-images{{< /copyable-code >}}

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idcontainer)

### Description

Container images used in GitHub Actions workflows must be pinned to immutable digests (SHA256) to ensure builds are repeatable and prevent malicious or accidental replacement of an image via mutable tags.

This rule checks the job-level `container.image` and each `services.<name>.image` entry for an image reference that includes a digest in the format `image@sha256:<hash>`. Image references that lack a digest or only use a tag, including `latest`, are considered unpinned.

If an image is provided via a workflow expression, such as `matrix` values, the expanded value must be a static digest. Complex or non-static expressions will be flagged. To remediate, replace tag-only references with a digest-pinned reference.

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
  # Case 1: Pinned container image (literal)
  test_pinned_container:
    runs-on: ubuntu-latest
    container:
      image: node@sha256:b4f0e0bdeb578043c518244e9f0f11f7e8b6d1a0f9f4e6e1e1f0a4f7c7e3c5a8
    steps:
      - run: npm test

  # Case 2: Pinned service image (literal)
  test_pinned_service:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres@sha256:c5e1c2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
    steps:
      - run: npm test

  # Case 3: Matrix-based expression with pinned images (container)
  test_matrix_pinned_container:
    strategy:
      matrix:
        image:
          - node@sha256:b4f0e0bdeb578043c518244e9f0f11f7e8b6d1a0f9f4e6e1e1f0a4f7c7e3c5a8
          - node@sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
    container:
      image: ${{ matrix.image }}
    runs-on: ubuntu-latest
    steps:
      - run: npm test

  # Case 4: Matrix-based expression with pinned images (service)
  test_matrix_pinned_service:
    strategy:
      matrix:
        db_image:
          - postgres@sha256:c5e1c2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
          - postgres@sha256:d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1c2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7
    runs-on: ubuntu-latest
    services:
      database:
        image: ${{ matrix.db_image }}
    steps:
      - run: npm test

  # Case 5: Expression-based service image (matrix with one unpinned image)
  test_matrix_unpinned_service_3:
    strategy:
      matrix:
        db_image: postgres@sha256:c5e1c2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
    runs-on: ubuntu-latest
    services:
      database:
        image: ${{ matrix.db_image }}
    steps:
      - run: npm test

  # Case 6: Expression-based service image (matrix with one unpinned image)
  test_matrix_unpinned_service_4:
    strategy:
      matrix:
        image: postgres
        tag: ["@sha256:c5e1c2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1", "@sha256:d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1c2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"]
    runs-on: ubuntu-latest
    services:
      database:
        image: ${{ format('{0}:{1}', matrix.image, matrix.tag) }}
    steps:
      - run: npm test

  # Case 7: Expression-based service image (matrix with one unpinned image)
  test_matrix_unpinned_service_4:
    strategy:
      matrix:
        image: postgres
    runs-on: ubuntu-latest
    services:
      database:
        image: ${{ format('{0}:@sha256:c5e1c2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1', matrix.image) }}
    steps:
      - run: npm test

```
## Non-Compliant Code Examples
```yaml
name: Unpinned Container Images
on: push

jobs:
  # Case 1: Literal unpinned container image
  test_unpinned_container:
    runs-on: ubuntu-latest
    container:
      image: node:18
    steps:
      - run: npm test

  # Case 2: Literal unpinned service image
  test_unpinned_service:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:14
    steps:
      - run: npm test

  # Case 3: Expression-based container image (matrix with unpinned images)
  test_matrix_unpinned_container:
    strategy:
      matrix:
        image: [node:18, node:20]
    container:
      image: ${{ matrix.image }}
    runs-on: ubuntu-latest
    steps:
      - run: npm test

  # Case 4: Expression-based service image (matrix with unpinned images)
  test_matrix_unpinned_service:
    strategy:
      matrix:
        db_image: [postgres:14, postgres:15]
    runs-on: ubuntu-latest
    services:
      database:
        image: ${{ matrix.db_image }}
    steps:
      - run: npm test

  # Case 5: Expression-based service image (matrix with one unpinned image)
  test_matrix_unpinned_service_2:
    strategy:
      matrix:
        db_image: [postgres:@sha256:14151617181920, postgres:15]
    runs-on: ubuntu-latest
    services:
      database:
        image: ${{ matrix.db_image }}
    steps:
      - run: npm test

  # Case 6: Expression-based service image (matrix with one unpinned image)
  test_matrix_unpinned_service_3:
    strategy:
      matrix:
        db_image: postgres:15
    runs-on: ubuntu-latest
    services:
      database:
        image: ${{ matrix.db_image }}
    steps:
      - run: npm test

  # Case 7: Expression-based service image (matrix with one unpinned image)
  test_matrix_unpinned_service_4:
    strategy:
      matrix:
        image: postgres
        tag: ["@sha256:8297842874987428", "15"]
    runs-on: ubuntu-latest
    services:
      database:
        image: ${{ format('{0}:{1}', matrix.image, matrix.tag) }}
    steps:
      - run: npm test

  # Case 8: Expression-based container image (non-matrix)
  test_expression_container:
    container:
      image: ${{ inputs.container_image }}
    runs-on: ubuntu-latest
    steps:
      - run: npm test

  # Case 9: Expression-based service image (non-matrix)
  test_expression_service:
    runs-on: ubuntu-latest
    services:
      cache:
        image: ${{ github.event.inputs.redis_image }}
    steps:
      - run: npm test

  # Case 10: Literal unpinned container image
  test_unpinned_container_no_image:
    runs-on: ubuntu-latest
    container: node:18
    steps:
      - run: npm test

```