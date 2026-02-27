---
title: "Using --platform flag with FROM command"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/using_platform_with_from"
  id: "b16e8501-ef3c-44e1-a543-a093238099c9"
  display_name: "Using --platform flag with FROM command"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `b16e8501-ef3c-44e1-a543-a093238099c9`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#from)

### Description

`FROM` instructions in Dockerfiles must not include the `--platform` flag. Overriding the target platform in the Dockerfile can cause builds to pull different, potentially unvetted or incompatible image variants, undermining image provenance, scanning, and supply-chain controls.

This rule checks `FROM` instructions and flags any use of the `--platform` flag. `FROM` lines should reference the intended image and tag without the `--platform` option. If a specific architecture is required, configure the build environment or manifest resolution outside the Dockerfile instead of embedding `--platform` in the instruction.

Secure example:

```dockerfile
FROM ubuntu:20.04
```

## Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN pip install --upgrade pip
LABEL maintainer="SvenDowideit@home.org.au"
COPY requirements.txt /usr/src/app/
FROM baseimage as baseimage-build

```
## Non-Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN pip install --upgrade pip
LABEL maintainer="SvenDowideit@home.org.au"
COPY requirements.txt /usr/src/app/
FROM --platform=arm64 baseimage as baseimage-build

```