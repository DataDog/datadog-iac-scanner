---
title: "Same alias in different FROM statements"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/same_alias_in_different_froms"
  id: "f2daed12-c802-49cd-afed-fe41d0b82fed"
  display_name: "Same alias in different FROM statements"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `f2daed12-c802-49cd-afed-fe41d0b82fed`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/multistage-build/)

### Description

`FROM` stage aliases must be unique because duplicate aliases make references such as `COPY --from=<alias>` ambiguous, which can cause incorrect artifacts or unintended files (including secrets) to be pulled into later stages and compromise image integrity.

Check every Dockerfile `FROM` command and ensure the token following `AS` (the stage alias) is distinct across all `FROM` commands. This rule flags cases where two or more `FROM` commands define the same alias. Resources without an `AS` alias are not affected. Ensure each multi-stage build uses a unique alias for each stage so stage references resolve unambiguously.

Secure example:

```dockerfile
FROM golang:1.20 AS builder
WORKDIR /src
RUN go build -o /app/myapp

FROM alpine:3.18 AS runtime
COPY --from=builder /app/myapp /usr/local/bin/myapp
```

## Compliant Code Examples
```dockerfile
FROM debian:jesse1 as build
RUN stuff

FROM debian:jesse1 as another-alias
RUN more_stuff

```
## Non-Compliant Code Examples
```dockerfile
FROM baseImage
RUN Test

FROM debian:jesse2 as build
RUN stuff

FROM debian:jesse1 as build
RUN more_stuff

```