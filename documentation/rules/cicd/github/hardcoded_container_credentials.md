---
title: "Hardcoded container credentials"
group_id: "CICD / GitHub"
meta:
  name: "github/hardcoded_container_credentials"
  id: "cicd-common-hardcoded-container-credentials"
  display_name: "Hardcoded container credentials"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `cicd-common-hardcoded-container-credentials`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idcontainercredentials)

### Description

Hardcoded container registry passwords in GitHub Actions workflows expose credentials to anyone with repository read access and embed secrets in version control history. This increases the risk of credential theft and unauthorized access to private images. Container credentials must be supplied via expressions that reference GitHub Secrets, such as `${{ secrets.DOCKER_PASSWORD }}`, rather than literal string values.

This check validates job-level container credentials `jobs[].container.credentials.password` and service container credentials `jobs[].services[].credentials.password` and will flag passwords that are plain literals instead of expression references. Values that parse as a GitHub Actions expression (curly-brace form) are allowed. Any password not written as an expression should be moved to a repository or organization secret and referenced from the workflow.

Secure configuration examples:

```yaml
jobs:
  build:
    container:
      image: my-registry/my-image:latest
      credentials:
        username: my-registry-user
        password: ${{ secrets.DOCKER_PASSWORD }}

    services:
      redis:
        image: redis:6
        credentials:
          username: redis-user
          password: ${{ secrets.REDIS_PASSWORD }}
```

## Compliant Code Examples
```yaml
name: Secure Container Credentials
on: push

jobs:
  test-container:
    runs-on: ubuntu-latest
    container:
      image: private.registry.com/image:latest
      credentials:
        username: ${{ secrets.REGISTRY_USER }}
        password: ${{ secrets.REGISTRY_PASSWORD }}
    steps:
      - run: echo "Running in container"
  test-service:
    runs-on: ubuntu-latest
    services:
      service1:
        credentials:
          username: ${{ secrets.REGISTRY_USER }}
          password: ${{ secrets.REGISTRY_PASSWORD }}
    steps:
      - run: echo "Running a service"

```
## Non-Compliant Code Examples
```yaml
name: Hardcoded Container Credentials
on: push

jobs:
  test-container:
    runs-on: ubuntu-latest
    container:
      image: private.registry.com/image:latest
      credentials:
        username: myuser
        password: mypassword123
    steps:
      - run: echo "Running in container"
  test-service:
    runs-on: ubuntu-latest
    services:
      service1:
        credentials:
          username: myuser
          password: mypassword123
    steps:
      - run: echo "Running a service"

```