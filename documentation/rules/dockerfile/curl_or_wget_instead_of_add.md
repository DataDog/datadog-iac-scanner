---
title: "curl or wget instead of ADD"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/curl_or_wget_instead_of_add"
  id: "4b410d24-1cbe-4430-a632-62c9a931cf1c"
  display_name: "curl or wget instead of ADD"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `4b410d24-1cbe-4430-a632-62c9a931cf1c`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)

### Description

Using Dockerfile `ADD` to download files from HTTPS URLs embeds externally hosted content into images without integrity checks and creates supply-chain and reproducibility risks if the remote resource changes or is compromised.

This rule flags Dockerfile `ADD` instructions whose source argument matches `http://` or `https://`. Instead, fetch remote artifacts with `curl` or `wget` in a `RUN` step, or use `COPY` for pre-downloaded local files.

When you download in the build, pin exact versions, validate integrity (for example, via SHA256 or signatures), and remove temporary files to avoid leaving unverified artifacts in the final image. 

Secure pattern example using `curl` with checksum verification:

```Dockerfile
# Secure: download with curl and verify SHA256 before extracting
RUN curl -fsSL https://example.com/package-1.2.3.tar.gz -o /tmp/package.tar.gz \
  && echo "expected_sha256  /tmp/package.tar.gz" | sha256sum -c - \
  && tar -xzf /tmp/package.tar.gz -C /usr/src/app \
  && rm /tmp/package.tar.gz
```

## Compliant Code Examples
```dockerfile
FROM openjdk:10-jdk
RUN mkdir -p /usr/src/things \
    && curl -SL https://example.com/big.tar.xz \
    | tar -xJC /usr/src/things \
    && make -C /usr/src/things all

```

```dockerfile
FROM openjdk:10-jdk
ADD ./drop-http-proxy-header.conf /etc/apache2/conf-available
RUN mkdir -p /usr/src/things \
    && curl -SL https://example.com/big.tar.xz \
    | tar -xJC /usr/src/things \
    && make -C /usr/src/things all

```
## Non-Compliant Code Examples
```dockerfile
FROM openjdk:10-jdk
VOLUME /tmp
ADD https://example.com/big.tar.xz /usr/src/things/
RUN tar -xJf /usr/src/things/big.tar.xz -C /usr/src/things
RUN make -C /usr/src/things all

```