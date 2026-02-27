---
title: "Multiple RUN, ADD, COPY instructions listed"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/multiple_run_add_copy_instructions_listed"
  id: "0008c003-79aa-42d8-95b8-1c2fe37dbfe6"
  display_name: "Multiple RUN, ADD, COPY instructions listed"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `0008c003-79aa-42d8-95b8-1c2fe37dbfe6`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://sysdig.com/blog/dockerfile-best-practices/)

### Description

Dockerfiles that use multiple consecutive `RUN`, `COPY`, or `ADD` instructions create extra image layers, which increases image size and can preserve intermediate artifacts (including secrets), raising the risk of sensitive data exposure and making images harder to scan.

This rule inspects Dockerfile instructions and flags adjacent `RUN` instructions or adjacent `COPY`/`ADD` instructions that target the same destination (the last argument) because these can be consolidated into single instructions to avoid extra layers. Group shell commands with `&&` into one `RUN`, and combine multiple sources into a single `COPY`/`ADD` that lists all source paths with one destination.

Secure examples:

```dockerfile
# Combine RUN commands
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*

# Combine COPY sources to a single destination
COPY config/app.conf config/db.conf /app/config/
```

## Compliant Code Examples
```dockerfile
FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go    ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
ADD cairo.spec /rpmbuild/SOURCES
ADD cairo-1.13.1.tar.xz /rpmbuild/SOURCES

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /go/src/github.com/foo/href-counter/app ./
CMD ["./app"]
RUN useradd -ms /bin/bash patrick

USER patrick

```

```dockerfile
FROM ubuntu
COPY README.md package.json gulpfile.js __BUILD_NUMBER ./

```

```dockerfile
FROM ubuntu
COPY README.md ./one
COPY package.json ./two
COPY gulpfile.js ./three
COPY __BUILD_NUMBER ./four

FROM ubuntu:1.2
ADD README.md ./one
ADD package.json ./two
ADD gulpfile.js ./three
ADD __BUILD_NUMBER ./four

```
## Non-Compliant Code Examples
```dockerfile
FROM ubuntu
COPY README.md ./
COPY package.json ./
COPY gulpfile.js ./
COPY __BUILD_NUMBER ./

```

```dockerfile
FROM ubuntu
RUN apt-get install -y wget
RUN wget https://…/downloadedfile.tar
RUN tar xvzf downloadedfile.tar
RUN rm downloadedfile.tar
RUN apt-get remove wget

```

```dockerfile
FROM ubuntu
ADD cairo.spec /rpmbuild/SOURCES
ADD cairo-1.13.1.tar.xz /rpmbuild/SOURCES
ADD cairo-multilib.patch /rpmbuild/SOURCES

```