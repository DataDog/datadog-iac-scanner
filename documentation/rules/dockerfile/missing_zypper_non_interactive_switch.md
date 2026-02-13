---
title: "Missing Zypper non-interactive switch"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/missing_zypper_non_interactive_switch"
  id: "45e1fca5-f90e-465d-825f-c2cb63fa3944"
  display_name: "Missing Zypper non-interactive switch"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Supply-Chain"
---
## Metadata

**Id:** `45e1fca5-f90e-465d-825f-c2cb63fa3944`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run)

### Description

`RUN` instructions that invoke the zypper package manager must include a non-interactive switch to avoid interactive prompts that can stall automated builds. This ensures package installs, removals, and patches complete reliably in CI/CD pipelines. Without this switch, images may be built with missing packages or without applied security updates.

Check Dockerfile `RUN` commands that call zypper subcommands (for example, `in`, `remove`/`rm`, `source-install`/`si`, and `patch`) and ensure the command includes either `-y` or `--no-confirm`. Any `RUN` command invoking zypper without one of these switches will be flagged. 

Secure examples:

```dockerfile
RUN zypper --no-confirm install ca-certificates
RUN zypper -y patch
```

## Compliant Code Examples
```dockerfile
FROM busybox:1.0
RUN zypper install -y httpd=2.4.46 && zypper clean
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1

```

```dockerfile
FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go    ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
RUN zypper install httpd && zypper clean

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
RUN zypper install httpd && zypper clean
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1

```