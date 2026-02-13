---
title: "Unpinned package version in apk add"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/unpinned_package_version_in_apk_add"
  id: "d3499f6d-1651-41bb-a9a7-de925fea487b"
  display_name: "Unpinned package version in apk add"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Supply-Chain"
---
## Metadata

**Id:** `d3499f6d-1651-41bb-a9a7-de925fea487b`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)

### Description

Alpine packages installed in Dockerfile `RUN` instructions should be version-pinned to prevent supply-chain risks and ensure reproducible builds. Unpinned packages can pull in newer, potentially vulnerable or incompatible versions on rebuilds.

This rule inspects Dockerfile `RUN` instructions that invoke `apk add` and requires each package token to use the pinning form `package=version`. Flags such as `--virtual`, `-t`, and short options like `-v` are ignored when identifying package names. Alphabetic tokens following `apk add` that are not option flags and do not include `=version` will be flagged.

Resources with packages like `apk add curl` (no version) will be reported. Update `RUN` lines to pin package versions.

Secure example:

```Dockerfile
RUN apk add --no-cache ca-certificates=20210512 curl=7.79.1
```

## Compliant Code Examples
```dockerfile
FROM alpine:3.4
RUN apk add --update py-pip=7.1.2-r0
RUN sudo pip install --upgrade pip
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

FROM alpine:3.1
RUN apk add py-pip=7.1.2-r0
RUN ["apk", "add", "py-pip=7.1.2-r0"]
RUN sudo pip install --upgrade pip
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

```

```dockerfile
FROM alpine:3.4
RUN apk add --update py-pip=7.1.2-r0
RUN sudo pip install --upgrade pip
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

FROM alpine:3.1
RUN apk add --virtual .test py-pip=7.1.2-r0
RUN apk --quiet --update --no-cache add libstdc++==11.2.1_git20220219-r2
RUN ["apk", "add", "--virtual .test", "py-pip=7.1.2-r0"]
RUN sudo pip install --upgrade pip
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

```
## Non-Compliant Code Examples
```dockerfile
FROM alpine:3.9
RUN apk add --update py-pip
RUN sudo pip install --upgrade pip
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
ENV TEST="test"
CMD ["python", "/usr/src/app/app.py"]

FROM alpine:3.7
RUN apk add py-pip && apk add tea
RUN apk add py-pip \
    && rm -rf /tmp/*
RUN apk add --dir /dir libimagequant \
    && minidlna
RUN ["apk", "add", "py-pip"]
RUN sudo pip install --upgrade pip
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python"]

```