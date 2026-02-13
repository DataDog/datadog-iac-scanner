---
title: "Multiple ENTRYPOINT instructions listed"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/multiple_entrypoint_instructions_listed"
  id: "6938958b-3f1a-451c-909b-baeee14bdc97"
  display_name: "Multiple ENTRYPOINT instructions listed"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `6938958b-3f1a-451c-909b-baeee14bdc97`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#entrypoint)

### Description

Dockerfiles must contain at most one `ENTRYPOINT` because only the last `ENTRYPOINT` instruction is applied and any earlier `ENTRYPOINT` instructions are silently ignored. Multiple `ENTRYPOINT` instructions can cause intended initialization, security wrappers, or startup controls to be bypassed, which may result in containers running unintended processes or reduced security protections.

This rule flags Dockerfiles that include more than one `ENTRYPOINT` instruction. Ensure the Dockerfile has a single `ENTRYPOINT` (for example, have the `ENTRYPOINT` invoke a wrapper script that performs initialization and then execs the main process). Resources with multiple `ENTRYPOINT` lines will be flagged.

Secure example using a single `ENTRYPOINT`:

```dockerfile
FROM alpine:3.18
COPY start.sh /usr/local/bin/start.sh
ENTRYPOINT ["/usr/local/bin/start.sh"]
CMD ["--serve"]
```

## Compliant Code Examples
```dockerfile
FROM golang:1.7.3
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
ENTRYPOINT [ "/opt/app/run.sh", "--port", "8080" ]

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=0 /go/src/github.com/foo/href-counter/app .
ENTRYPOINT [ "/opt/app/run.sh", "--port", "8080" ]
```

```dockerfile
FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go    ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
ENTRYPOINT [ "/opt/app/run.sh", "--port", "8080" ]
ENTRYPOINT [ "/opt/app/run.sh", "--port", "8000" ]

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
ENTRYPOINT [ "/opt/app/run.sh", "--port", "8080" ]
ENTRYPOINT [ "/opt/app/run.sh", "--port", "8000" ]

```