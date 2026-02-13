---
title: "Run using wget and curl"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/run_using_wget_and_curl"
  id: "fc775e75-fcfb-4c98-b2f2-910c5858b359"
  display_name: "Run using wget and curl"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** `fc775e75-fcfb-4c98-b2f2-910c5858b359`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run)

### Description

Including both `wget` and `curl` in the same Dockerfile increases image size and attack surface and encourages inconsistent or duplicate download logic that can lead to insecure fetches or maintenance errors.

This rule checks Dockerfile `RUN` instructions and flags images where `RUN` commands invoke both the `wget` and `curl` utilities (either as separate commands in a single `RUN` line or in exec-form `RUN` where the command is `wget` or `curl`). Resources will be flagged when any `RUN` instruction contains occurrences of both `wget` and `curl`. Instead, use a single downloader and ensure downloads are verified (TLS and checksum validation) rather than keeping both tools. 

Secure examples using only one downloader:

```dockerfile
# Use curl only
RUN curl -fSL https://example.com/install.sh -o /tmp/install.sh && \
    sha256sum -c /tmp/install.sh.sha256 && \
    sh /tmp/install.sh
```

```dockerfile
# Use wget only
RUN wget -qO /tmp/install.sh https://example.com/install.sh && \
    echo "checksum  /tmp/install.sh" | sha256sum -c - && \
    sh /tmp/install.sh
```

## Compliant Code Examples
```dockerfile
FROM debian
RUN curl http://google.com
RUN curl http://bing.com
RUN ["curl", "http://bing.com"]

```
## Non-Compliant Code Examples
```dockerfile
FROM debian
RUN wget http://google.com
RUN curl http://bing.com

FROM baseImage
RUN wget http://test.com
RUN curl http://bing.com
RUN ["curl", "http://bing.com"]

```