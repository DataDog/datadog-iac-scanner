---
title: "pip install keeping cached packages"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/pip_install_keeping_cached_packages"
  id: "f2f903fb-b977-461e-98d7-b3e2185c6118"
  display_name: "pip install keeping cached packages"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `f2f903fb-b977-461e-98d7-b3e2185c6118`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)

### Description

Dockerfile `RUN` instructions that invoke `pip` or `pip3` should include the `--no-cache-dir` flag to prevent pip from leaving downloaded package caches in image layers. This increases image size and can retain unnecessary artifacts that broaden the attack surface and complicate image hygiene.

This rule inspects Dockerfile `RUN` commands and flags any `RUN` that calls `pip` or `pip3` with an `install` subcommand but does not include `--no-cache-dir`. Both shell-form and exec-form `RUN` entries are checked. Resources missing the flag or using `pip`/`pip3 install` without `--no-cache-dir` will be reported.

Secure example:

```dockerfile
RUN pip install --no-cache-dir -r requirements.txt
```

## Compliant Code Examples
```dockerfile
FROM python:3
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir nibabel pydicom matplotlib pillow && \
    pip install --no-cache-dir med2image
RUN pip3 install --no-cache-dir requests=2.7.0
RUN ["pip3", "install", "requests=2.7.0", "--no-cache-dir"]
CMD ["cat", "/etc/os-release"]

```
## Non-Compliant Code Examples
```dockerfile
FROM python:3
RUN pip install --upgrade pip && \
    pip install nibabel pydicom matplotlib pillow && \
    pip install med2image
CMD ["cat", "/etc/os-release"]

FROM python:3.1
RUN pip install --upgrade pip
RUN python -m pip install nibabel pydicom matplotlib pillow
RUN pip3 install requests=2.7.0
RUN ["pip3", "install", "requests=2.7.0"]
CMD ["cat", "/etc/os-release"]

```