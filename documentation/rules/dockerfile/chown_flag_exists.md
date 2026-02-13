---
title: "chown flag exists"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/chown_flag_exists"
  id: "aa93e17f-b6db-4162-9334-c70334e7ac28"
  display_name: "chown flag exists"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `aa93e17f-b6db-4162-9334-c70334e7ac28`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)

### Description

Setting file ownership to a non-root user in a Dockerfile using the `--chown` flag can leave executables or sensitive files writable by the runtime user. This can enable tampering, persistence of malicious artifacts, or privilege escalation.

This rule flags Dockerfile instructions (for example, `COPY` or `ADD`) that include the `--chown` flag; Dockerfile commands must not use `--chown`. To remediate, remove `--chown` from `COPY`/`ADD` and ensure files remain root-owned with restrictive permissions (for example, use `RUN chmod`), or perform any necessary, controlled ownership changes at container startup rather than using `--chown` in image build.

Secure example:

```dockerfile
# Copy files without --chown so they remain owned by root in the image
COPY app/mybinary /usr/local/bin/mybinary
RUN chmod 0555 /usr/local/bin/mybinary
```

## Compliant Code Examples
```dockerfile
FROM python:3.7
RUN pip install Flask==0.11.1
RUN useradd -ms /bin/bash patrick
COPY app /app
WORKDIR /app
USER patrick
CMD ["python", "app.py"]

```
## Non-Compliant Code Examples
```dockerfile
FROM python:3.7
RUN pip install Flask==0.11.1
RUN useradd -ms /bin/bash patrick
COPY --chown=patrick:patrick app /app
WORKDIR /app
USER patrick
CMD ["python", "app.py"]

```