---
title: "yum clean all missing"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/yum_clean_all_missing"
  id: "00481784-25aa-4a55-8633-3136dfcf4f37"
  display_name: "yum clean all missing"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `00481784-25aa-4a55-8633-3136dfcf4f37`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run)

### Description

Dockerfile `RUN` instructions that perform a `yum install` must run `yum clean all` afterward to remove package manager caches and reduce image size. This prevents unnecessarily large images and the retention of cached packages or metadata that can increase attack surface.

This rule checks Dockerfile `RUN` commands containing `yum ... install` and requires that `yum clean all` appears later in the same `RUN` instruction. `RUN` lines with `yum install` but no subsequent `yum clean all` (or with `yum clean all` positioned before the install) will be flagged. If you perform multiple installs, ensure a single `yum clean all` follows them in the same `RUN`, or explicitly remove `/var/cache/yum` as part of the same command to guarantee caches are deleted.

Secure example:

```Dockerfile
RUN yum -y install package1 package2 && yum clean all && rm -rf /var/cache/yum
```

## Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN yum install \
    yum clean all
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

FROM alpine:3.4
RUN yum -y install \
    yum clean all

```

```dockerfile
FROM golang:1.16 AS builder
WORKDIR /go/src/github.com/foo/href-counter/
RUN go get -d -v golang.org/x/net/html  
COPY app.go    ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .
RUN yum clean all \
    yum -y install

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
FROM alpine:3.5
RUN apk add --update py2-pip
RUN yum install
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

FROM alpine:3.4
RUN yum clean all \
    yum -y install

```