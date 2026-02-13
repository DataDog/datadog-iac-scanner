---
title: "gem install without version"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/gem_install_without_version"
  id: "22cd11f7-9c6c-4f6e-84c0-02058120b341"
  display_name: "gem install without version"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Supply-Chain"
---
## Metadata

**Id:** `22cd11f7-9c6c-4f6e-84c0-02058120b341`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run)

### Description

Unpinned Ruby gem installs in Dockerfile `RUN` commands allow unintentional upgrades or malicious releases to be pulled at build time, increasing risk of supply-chain compromise and causing non-reproducible or breakage-prone images.

This rule inspects Dockerfile `RUN` instructions that invoke `gem install` and requires each gem to include an explicit version, for example, via `-v <version>` or `--version <version>` (or other recognized inline version syntax). Both single-line `RUN` strings and tokenized `RUN` commands are analyzed. Any gem argument that is a plain package name without a following version flag or embedded version will be flagged. 

Secure examples:

```dockerfile
RUN gem install bundler -v 2.3.7 rake -v 13.0.6
RUN gem install rails --version '6.1.7'
```

## Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN gem install bundler:2.0.2
RUN bundle install
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]
ENV GRPC_VERSION 1.0.0
RUN gem install grpc -v ${GRPC_RUBY_VERSION}
RUN gem install grpc:${GRPC_VERSION} grpc-tools:${GRPC_VERSION}

```
## Non-Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN gem install bundler
RUN ["gem", "install", "blunder"]
RUN gem install grpc -v ${GRPC_RUBY_VERSION} blunder
RUN bundle install
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

```