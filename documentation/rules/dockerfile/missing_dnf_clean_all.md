---
title: "Missing dnf clean all"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/missing_dnf_clean_all"
  id: "295acb63-9246-4b21-b441-7c1f1fb62dc0"
  display_name: "Missing dnf clean all"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `295acb63-9246-4b21-b441-7c1f1fb62dc0`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)

### Description

When Dockerfile `RUN` commands install packages with DNF and do not remove package caches, the resulting image retains package metadata and cached packages which increase image size and can broaden the attack surface or complicate vulnerability management.

This rule checks Dockerfile `RUN` instructions: any `RUN` that contains a `dnf install` command (including variants such as `dnf in`, `dnf reinstall`, `dnf rei`, `dnf install-n`, `dnf install-na`, `dnf install-nevra`) must be followed by a `dnf clean all` invocation. The `dnf clean all` may appear in the same `RUN` (recommended, chained with `&&`) or in a subsequent `RUN` later in the Dockerfile. `RUN` commands that perform a dnf install but have no later `RUN` containing `dnf clean` will be flagged. 

Secure example with cleanup in the same `RUN`:

```
FROM fedora:latest
RUN dnf -y install my-package && dnf clean all && rm -rf /var/cache/dnf
```

## Compliant Code Examples
```dockerfile
FROM fedora:27
RUN set -uex && \
    dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo && \
    sed -i 's/\$releasever/26/g' /etc/yum.repos.d/docker-ce.repo && \
    dnf install -vy docker-ce && \
    dnf clean all
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1

```

```dockerfile
FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go    ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
RUN set -uex && \
    dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo && \
    sed -i 's/\$releasever/26/g' /etc/yum.repos.d/docker-ce.repo && \
    dnf install -vy docker-ce

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /go/src/github.com/foo/href-counter/app ./
CMD ["./app"]
RUN useradd -ms /bin/bash patrick

USER patrick

```
## Non-Compliant Code Examples
```dockerfile
FROM fedora:27
RUN set -uex && \
    dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo && \
    sed -i 's/\$releasever/26/g' /etc/yum.repos.d/docker-ce.repo && \
    dnf install -vy docker-ce
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1

```