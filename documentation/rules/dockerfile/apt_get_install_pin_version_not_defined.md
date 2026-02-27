---
title: "apt-get install pin version not defined"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/apt_get_install_pin_version_not_defined"
  id: "965a08d7-ef86-4f14-8792-4a3b2098937e"
  display_name: "apt-get install pin version not defined"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Supply-Chain"
---
## Metadata

**Id:** `965a08d7-ef86-4f14-8792-4a3b2098937e`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)

### Description

Installing packages in a Dockerfile without pinning versions can lead to unintentional upgrades or supply-chain changes that introduce vulnerabilities or break reproducible builds.

This rule inspects Dockerfile `RUN` instructions that invoke `apt-get install` and flags any package tokens that do not include an explicit version (for APT, the expected form is `name=version`). Resources with packages missing `=version` will be reported. Ensure every package in the `apt-get install` invocation is pinned to a specific version instead of relying on the distribution's default. 

Secure example:

```dockerfile
RUN apt-get update && apt-get install -y \
  curl=7.68.0-1ubuntu2 \
  nginx=1.18.0-0ubuntu1
```

## Compliant Code Examples
```dockerfile
FROM busybox
RUN apt-get install python=2.7
```

```dockerfile
FROM busyboxneg2
RUN apt-get install python=2.7

FROM busyboxneg3
RUN apt-get install -y -t python=2.7

FROM busyboxneg4
RUN apt-get update; \
    apt-get install -y \
    python-qt4=4.11 \
    python-pyside=6.0.1 \
    python-pip=1.0.2 \
    python3-pip=1.0 \
    python3-pyqt5=5

```

```dockerfile
FROM busybox
RUN apt-get install python=2.7 ; echo "A" && echo "B"
```
## Non-Compliant Code Examples
```dockerfile
FROM busybox4
RUN apt-get install python
RUN ["apt-get", "install", "python"]

FROM busybox5
RUN apt-get install -y -t python

FROM busybox6
RUN apt-get update ; \
    apt-get install -y \
    python-qt4 \
    python-pyside \
    python-pip \
    python3-pip \
    python3-pyqt5

```

```dockerfile
FROM busybox
RUN apt-get install python
RUN ["apt-get", "install", "python"]

FROM busybox2
RUN apt-get install -y -t python

FROM busybox3
RUN apt-get update && apt-get install -y \
    python-qt4 \
    python-pyside \
    python-pip \
    python3-pip \
    python3-pyqt5

```