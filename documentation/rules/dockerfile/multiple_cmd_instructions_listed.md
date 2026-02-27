---
title: "Multiple CMD instructions listed"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/multiple_cmd_instructions_listed"
  id: "41c195f4-fc31-4a5c-8a1b-90605538d49f"
  display_name: "Multiple CMD instructions listed"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `41c195f4-fc31-4a5c-8a1b-90605538d49f`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#cmd)

### Description

Dockerfiles must contain at most one `CMD` instruction because only the last `CMD` is used at container runtime. Extra `CMD` instructions are ignored and can cause required startup steps or security controls to be skipped, resulting in unexpected or insecure runtime behavior.

This rule flags Dockerfile documents that include more than one `CMD` instruction. Ensure your Dockerfile defines zero or one `CMD`. If you need multiple initialization steps, combine them into a single `CMD` (exec form), use `ENTRYPOINT` for the main process and `CMD` for default arguments, or run a wrapper script that performs setup and then execs the main process.

Secure examples:

```dockerfile
# single exec-form CMD
CMD ["nginx", "-g", "daemon off;"]
```

```dockerfile
# ENTRYPOINT for main process, CMD for defaults/arguments
ENTRYPOINT ["/usr/local/bin/start.sh"]
CMD ["--config", "/etc/app/config"]
```

## Compliant Code Examples
```dockerfile
FROM golang:1.7.3
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
CMD ["./app"] 

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=0 /go/src/github.com/foo/href-counter/app .
CMD ["./app"] 
```

```dockerfile
FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go    ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
CMD ["./app"] 
CMD ["./apps"] 

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
FROM golang:1.7.3
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=0 /go/src/github.com/foo/href-counter/app .
CMD ["./app"] 
CMD ["./apps"] 

```