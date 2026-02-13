---
title: "Missing user instruction"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/missing_user_instruction"
  id: "fd54f200-402c-4333-a5a4-36ef6709af2f"
  display_name: "Missing user instruction"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "HIGH"
  category: "Build Process"
---
## Metadata

**Id:** `fd54f200-402c-4333-a5a4-36ef6709af2f`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** High

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#user)

### Description

Specify a non-root user in the Dockerfile so containers do not run as root by default, which reduces the blast radius of a compromise and prevents easy privilege escalation.

This check inspects every build stage (excluding stages based on `scratch`) and flags the Dockerfile when no `USER` instruction appears in any stage. The Dockerfile must include a `USER` instruction that names a non-root user (username or numeric UID), preferably set in the final stage. Resources missing `USER` will be flagged.

This rule detects the absence of a `USER` instruction but does not validate the value—ensure the user is not `root` or UID `0` and that the user account is created in the image before switching to it.

Secure example:

```dockerfile
FROM python:3.11-slim AS builder
# build steps...
FROM python:3.11-slim
RUN groupadd -r app && useradd -r -g app app
COPY --from=builder /app /app
USER app
CMD ["python", "/app/app.py"]
```

## Compliant Code Examples
```dockerfile
FROM python:2.7
RUN pip install Flask==0.11.1
RUN useradd -ms /bin/bash patrick
COPY --chown=patrick:patrick app /app
WORKDIR /app
USER patrick
CMD ["python", "app.py"]

FROM scratch
RUN pip install Flask==0.11.1
RUN useradd -ms /bin/bash patrick
COPY --chown=patrick:patrick app /app
WORKDIR /app
CMD ["python", "app.py"]

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

```

```dockerfile
FROM python:2.7
RUN pip install Flask==0.11.1
RUN useradd -ms /bin/bash patrick
COPY --chown=patrick:patrick app /app
WORKDIR /app
USER patrick
CMD ["python", "app.py"]

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

```

```dockerfile
FROM python:2.7
RUN pip install Flask==0.11.1
RUN useradd -ms /bin/bash patrick
COPY --chown=patrick:patrick app /app
WORKDIR /app
CMD ["python", "app.py"]

```