---
title: "apt-get install lists were not deleted"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/apt_get_install_lists_were_not_deleted"
  id: "df746b39-6564-4fed-bf85-e9c44382303c"
  display_name: "apt-get install lists were not deleted"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** `df746b39-6564-4fed-bf85-e9c44382303c`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)

### Description

Leaving apt package lists in a built image after running `apt-get install` can expose package metadata and increase image size. This makes images larger to distribute and can retain information that aids attackers or troubleshooting of past package states.

This rule scans Dockerfile `RUN` instructions that invoke `apt-get install` and requires that the same `RUN` command perform cleanup by running `apt-get clean` and/or removing `/var/lib/apt/lists/*` (for example, `rm -rf /var/lib/apt/lists/*`). Ensure the cleanup step appears after the install in the same `RUN` (using `&&` or `;`) so the cache is not preserved in an earlier layer. 

Secure example:

```Dockerfile
RUN apt-get update && apt-get install -y curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
```

## Compliant Code Examples
```dockerfile
FROM busyboxneg1
RUN apt-get update && apt-get install --no-install-recommends -y python \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

FROM busyboxneg2
RUN apt-get update && apt-get install --no-install-recommends -y python && apt-get clean

FROM busyboxneg3
RUN apt-get update && apt-get install --no-install-recommends -y python \
  && apt-get clean

FROM busyboxneg4
RUN apt-get update && apt-get install --no-install-recommends -y python \
  && rm -rf /var/lib/apt/lists/*

```

```dockerfile
FROM busyboxneg5
RUN apt-get update; \
  apt-get install --no-install-recommends -y python; \
  apt-get clean; \
  rm -rf /var/lib/apt/lists/*

FROM busyboxneg6
RUN apt-get update; \
  apt-get install --no-install-recommends -y python; \
  apt-get clean

FROM busyboxneg7
RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends package=0.0.0; \
	rm -rf /var/lib/apt/lists/*

```
## Non-Compliant Code Examples
```dockerfile
FROM busybox5
RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends package=0.0.0

```

```dockerfile
FROM busybox1
RUN apt-get update && apt-get install --no-install-recommends -y python

FROM busybox2
RUN apt-get install python

FROM busybox3
RUN apt-get update && apt-get install --no-install-recommends -y python
RUN rm -rf /var/lib/apt/lists/*

FROM busybox4
RUN apt-get update && apt-get install --no-install-recommends -y python
RUN rm -rf /var/lib/apt/lists/*
RUN apt-get clean

```