---
title: "Run using sudo"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/run_using_sudo"
  id: "8ada6e80-0ade-439e-b176-0b28f6bce35a"
  display_name: "Run using sudo"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `8ada6e80-0ade-439e-b176-0b28f6bce35a`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#run)

### Description

Including the `sudo` command in Dockerfile `RUN` instructions is a misconfiguration because Docker build steps typically run as root and `sudo` is unnecessary. Using `sudo` can mask incorrect privilege assumptions and lead to fragile builds, unexpected file ownership, or build-time failures when `sudo` is not available.

This rule flags Dockerfile `RUN` instructions that contain the literal `sudo`, either as the first token or anywhere in the command value. `RUN` instructions must omit `sudo`. Fix by invoking commands directly during build or by switching to a non-root user with the `USER` directive and correcting permissions with `chown` where appropriate.

```Dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl

# If commands must run as a non-root user:
USER appuser
RUN mkdir -p /app && chown appuser:appuser /app
```

## Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN pip install --upgrade pip
RUN apt-get install sudo
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]

```
## Non-Compliant Code Examples
```dockerfile
FROM alpine:3.5
RUN apk add --update py2-pip
RUN sudo pip install --upgrade pip
COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
COPY app.py /usr/src/app/
COPY templates/index.html /usr/src/app/templates/
EXPOSE 5000
CMD ["python", "/usr/src/app/app.py"]
```