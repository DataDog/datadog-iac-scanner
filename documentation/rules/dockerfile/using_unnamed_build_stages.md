---
title: "Using unnamed build stages"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/using_unnamed_build_stages"
  id: "68a51e22-ae5a-4d48-8e87-b01a323605c9"
  display_name: "Using unnamed build stages"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `68a51e22-ae5a-4d48-8e87-b01a323605c9`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/multistage-build/)

### Description

`COPY` instructions should reference a named build stage alias instead of a numeric stage index. Numeric references are brittle because reordering or inserting stages can change which stage is referenced, potentially causing unintended files or secrets from another stage to be copied into the final image.

This rule examines Dockerfile `COPY` commands that use the `--from` flag and flags cases where the `--from` value is a numeric index. The `--from` argument must be a previously defined `FROM ... AS <name>` alias (a non-numeric name).

`COPY` instructions with `--from=<number>` (for example, `--from=2`) will be flagged. Ensure each build stage defines an alias with `AS <name>` and reference that alias in `COPY --from=<alias>`.

Secure example using a named stage alias:

```dockerfile
FROM golang:1.18 AS builder
WORKDIR /app
COPY . .
RUN go build -o app

FROM alpine:3.16
COPY --from=builder /app/app /usr/local/bin/app
CMD ["/usr/local/bin/app"]
```

## Compliant Code Examples
```dockerfile
FROM golang:1.7.3 AS builder
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html
COPY app.go    .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

# another dockerfile
FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /go/src/github.com/foo/href-counter/app .
CMD ["./app"]

```
## Non-Compliant Code Examples
```dockerfile
FROM golang:1.16
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=0 /go/src/github.com/foo/href-counter/app ./
CMD ["./app"] 

```