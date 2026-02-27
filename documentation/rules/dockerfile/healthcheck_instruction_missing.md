---
title: "Healthcheck instruction missing"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/healthcheck_instruction_missing"
  id: "b03a748a-542d-44f4-bb86-9199ab4fd2d5"
  display_name: "Healthcheck instruction missing"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `b03a748a-542d-44f4-bb86-9199ab4fd2d5`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#healthcheck)

### Description

Containers should expose an explicit `HEALTHCHECK` so runtimes and orchestrators can detect unhealthy applications and automatically restart or replace failing containers. Without a health check, internal failures may go unnoticed and lead to reduced availability and slower incident recovery.

This rule verifies each Dockerfile build stage (each `FROM`) and requires a `HEALTHCHECK` instruction to be present in the stage's instruction set. Stages missing a `HEALTHCHECK` will be flagged.

Implement the `HEALTHCHECK` using the `CMD` form and sensible options (for example, `--interval`, `--timeout`, `--start-period`, `--retries`) so the probe is lightweight and accurately reflects service health.

Secure example:

```dockerfile
FROM alpine:3.14
# application setup...

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://localhost:8080/health || exit 1
```

## Compliant Code Examples
```dockerfile
FROM node:alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1 
CMD ["node","app.js"]
```

```dockerfile
FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go    ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /go/src/github.com/foo/href-counter/app ./
CMD ["./app"]
RUN useradd -ms /bin/bash patrick

USER patrick
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1 

```
## Non-Compliant Code Examples
```dockerfile
FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go    ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /go/src/github.com/foo/href-counter/app ./
CMD ["./app"]
RUN useradd -ms /bin/bash patrick

USER patrick

```

```dockerfile
FROM node:alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["node","app.js"]
```