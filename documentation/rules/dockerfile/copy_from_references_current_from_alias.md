---
title: "COPY --from references current FROM alias"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/copy_from_references_current_from_alias"
  id: "cdddb86f-95f6-4fc4-b5a1-483d9afceb2b"
  display_name: "COPY --from references current FROM alias"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `cdddb86f-95f6-4fc4-b5a1-483d9afceb2b`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/multistage-build/)

### Description

`COPY` commands with the `--from` flag must not reference the alias of the stage in which the `COPY` appears. Referencing the current `FROM` alias is logically invalid (a stage cannot copy from itself) and can cause build failures or produce images with missing or incorrect artifacts, which may lead to broken or insecure deployments.

The check examines Dockerfile `FROM` stages that define an alias (`FROM <image> AS <alias>`) and flags `COPY` commands whose `--from=<alias>` value equals the alias of the current stage. Resources with `COPY --from` set to the same stage alias will be flagged; fix by removing `--from` to copy from the current stage or by specifying a different stage name or external image as the `--from` source.

Secure example copying from a different build stage:

```Dockerfile
FROM golang:1.18 AS builder
WORKDIR /app
RUN go build -o app

FROM alpine:3.16 AS runtime
COPY --from=builder /app/app /usr/local/bin/app
CMD ["app"]
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
FROM myimage:tag as dep
COPY --from=dep /binary /
RUN dir c:\ 
```