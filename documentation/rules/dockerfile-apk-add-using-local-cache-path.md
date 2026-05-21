---
title: "apk add using local cache path"
group_id: "Dockerfile"
meta:
  name: "apk_add_using_local_cache_path"
  id: "dockerfile-apk-add-using-local-cache-path"
  display_name: "apk add using local cache path"
  cloud_provider: ""
  platform: "Dockerfile"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** {{< copyable-code >}}dockerfile-apk-add-using-local-cache-path{{< /copyable-code >}}

**Platform:** Dockerfile

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#run)

### Description

Alpine package installs in Dockerfile `RUN` instructions must include the `--no-cache` flag to avoid persisting the package index and cache in image layers. Retaining this data increases image size and can preserve stale metadata that widens the attack surface with outdated or vulnerable package information.

This rule inspects Dockerfile `RUN` commands and flags any `apk add` invocation that does not include the `--no-cache` option. Fix by adding `--no-cache` to the `apk add` command or by ensuring the cache is removed in the same layer; using `--no-cache` is preferred to prevent the cache from being written at all. Resources with `apk add` and no `--no-cache` will be flagged.

Secure example:

```
RUN apk add --no-cache curl git ca-certificates
```

## Compliant Code Examples
```dockerfile
FROM gliderlabs/alpine:3.3
RUN apk add --no-cache python
WORKDIR /app
ONBUILD COPY . /app
ONBUILD RUN virtualenv /env && /env/bin/pip install -r /app/requirements.txt
EXPOSE 8080
CMD ["/env/bin/python", "main.py"]
```

```dockerfile
FROM gliderlabs/alpine:3.3
RUN apk add --no-cache python
WORKDIR /app
ONBUILD COPY . /app
ONBUILD RUN virtualenv /env; \
    /env/bin/pip install -r /app/requirements.txt
EXPOSE 8080
CMD ["/env/bin/python", "main.py"]

```
## Non-Compliant Code Examples
```dockerfile
FROM gliderlabs/alpine:3.3
RUN apk add --update-cache python
WORKDIR /app
ONBUILD COPY . /app
ONBUILD RUN virtualenv /env; \
    /env/bin/pip install -r /app/requirements.txt
EXPOSE 8080
CMD ["/env/bin/python", "main.py"]

```

```dockerfile
FROM gliderlabs/alpine:3.3
RUN apk add --update-cache python
WORKDIR /app
ONBUILD COPY . /app
ONBUILD RUN virtualenv /env && /env/bin/pip install -r /app/requirements.txt
EXPOSE 8080
CMD ["/env/bin/python", "main.py"]
```