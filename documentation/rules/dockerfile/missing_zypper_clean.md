---
title: "Missing zypper clean"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/missing_zypper_clean"
  id: "38300d1a-feb2-4a48-936a-d1ef1cd24313"
  display_name: "Missing zypper clean"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `38300d1a-feb2-4a48-936a-d1ef1cd24313`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run)

### Description

Dockerfile `RUN` instructions that invoke zypper must include a subsequent `zypper clean` to remove package manager caches. Cached packages and metadata are otherwise persisted in image layers, increasing image size and the chance of leaking repository metadata or outdated package data.

This rule checks Dockerfile `RUN` commands for zypper usage (for example, `zypper in`, `zypper install`, `zypper rm`, `zypper si`, and `zypper patch`) and requires a `zypper clean` or `zypper cc` either in the same `RUN` command after the install or in a later `RUN` within the same build stage. Resources that run zypper without a following clean (or that rely on a clean in a prior layer) will be flagged. To avoid leaving caches in intermediate layers, chain the install and clean steps in the same `RUN`.

Secure example:

```dockerfile
FROM opensuse/leap
RUN zypper -n refresh && \
    zypper -n install package1 package2 && \
    zypper clean
```

## Compliant Code Examples
```dockerfile
FROM busybox:1.0
RUN zypper install -y httpd=2.4 && zypper clean
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1

```

```dockerfile
FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go    ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
RUN zypper install

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
FROM busybox:1.0
RUN zypper install
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1

```