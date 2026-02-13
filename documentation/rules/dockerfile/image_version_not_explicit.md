---
title: "Image version not explicit"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/image_version_not_explicit"
  id: "9efb0b2d-89c9-41a3-91ca-dcc0aec911fd"
  display_name: "Image version not explicit"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Supply-Chain"
---
## Metadata

**Id:** `9efb0b2d-89c9-41a3-91ca-dcc0aec911fd`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#from)

### Description

Dockerfile `FROM` instructions must specify an explicit image tag or digest to ensure build reproducibility and reduce supply-chain risk from unexpected upstream image updates.

Check each Dockerfile `FROM` command: the image reference must include a tag (`image:tag`) or a content-addressable digest (`image@sha256:<digest>`). Literal image names without a tag or digest will be flagged. When the image is supplied via `ARG` or `ENV` (for example, `FROM $BASE` or `FROM ${BASE}`), verify the corresponding `ARG`/`ENV` value is defined and contains the tag or digest.

The special base `scratch` and `FROM` lines that reference a previously declared build stage by name are exempt from this requirement. Resources missing a tag or digest (no `:` or `@`) will be reported.

Secure examples:

```dockerfile
FROM ubuntu:20.04

ARG BASE=nginx:1.21.6
FROM ${BASE}

FROM nginx@sha256:3a1b8f2e...  
```

## Compliant Code Examples
```dockerfile
FROM ubuntu:22.04 AS test
RUN echo "hello"

FROM test AS build
RUN echo "build"

FROM build AS final
RUN echo "final"
```

```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN pip install --upgrade pip
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
ARG IMAGE=alpine:3.12
FROM $IMAGE
CMD ["python", "/usr/src/app/app.py"]

```
## Non-Compliant Code Examples
```dockerfile
FROM ubuntu:22.04 AS test
RUN echo "hello"

FROM test AS build
RUN echo "build"

FROM construction AS final
RUN echo "final"
```

```dockerfile
FROM alpine
RUN apk add --update py2-pip
RUN pip install --upgrade pip
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"] 
```