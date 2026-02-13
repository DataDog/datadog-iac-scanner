---
title: "Image version using latest"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/image_version_using_latest"
  id: "f45ea400-6bbe-4501-9fc7-1c3d75c32067"
  display_name: "Image version using latest"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `f45ea400-6bbe-4501-9fc7-1c3d75c32067`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/dev-best-practices/)

### Description

Using the `:latest` tag for base images makes builds non-reproducible and can silently introduce unreviewed or vulnerable changes from upstream, increasing supply-chain and runtime risk.

Check the Dockerfile `FROM` instruction: the image reference must use an explicit version tag or an immutable digest (for example, `nginx:1.21.6` or `nginx@sha256:...`) rather than `...:latest`. `scratch` base images are exempt.

This rule flags `FROM` lines that contain `:latest` (excluding `scratch`). Update them to a specific semantic version tag or pin to a digest to ensure consistent, auditable images. 

Secure examples:

```Dockerfile
FROM nginx:1.21.6
```

```Dockerfile
FROM nginx@sha256:03a1c7c8f9e2d5b6a7c8e9f0a1b2c3d4e5f67890123456789abcdef0123456789
```

## Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN pip install --upgrade pip
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]
```
## Non-Compliant Code Examples
```dockerfile
FROM alpine:latest
RUN apk add --update py2-pip
RUN pip install --upgrade pip
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]
```