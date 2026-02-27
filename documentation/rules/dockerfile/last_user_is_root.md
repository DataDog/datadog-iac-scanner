---
title: "Last user is root"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/last_user_is_root"
  id: "67fd0c4a-68cf-46d7-8c41-bc9fba7e40ae"
  display_name: "Last user is root"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "HIGH"
  category: "Best Practices"
---
## Metadata

**Id:** `67fd0c4a-68cf-46d7-8c41-bc9fba7e40ae`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** High

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#user)

### Description

Containers must not run their final process as root because running as root increases the impact of a compromise and can enable privilege escalation or container-to-host attacks.

This rule checks the Dockerfile `USER` instruction and flags Dockerfiles whose last `USER` is set to `root`. The final `USER` must be a non-root username or UID.

If root is required for build-time actions, perform those steps earlier (for example, in a build stage), then create a non-root user and set `USER` to that account before the final `CMD`/`ENTRYPOINT`. 

Secure example that switches to a non-root user before runtime:

```dockerfile
FROM node:18 AS build
RUN npm ci && npm run build

FROM node:18-slim
WORKDIR /app
COPY --from=build /app/dist .
RUN addgroup --system app && adduser --system --ingroup app app
USER app
CMD ["node", "server.js"]
```

## Compliant Code Examples
```dockerfile
FROM alpine:2.6
USER root
RUN npm install
USER guest
```

```dockerfile
FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go    ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
USER root

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
FROM alpine:2.6
USER root
RUN npm install
```