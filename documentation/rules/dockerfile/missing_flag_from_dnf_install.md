---
title: "Missing flag from dnf install"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/missing_flag_from_dnf_install"
  id: "7ebd323c-31b7-4e5b-b26f-de5e9e477af8"
  display_name: "Missing flag from dnf install"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** `7ebd323c-31b7-4e5b-b26f-de5e9e477af8`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run)

### Description

DNF package installations in Dockerfile `RUN` instructions can prompt for interactive input. If the installer is run without a non-interactive flag, the build can hang or fail, disrupting automated CI/CD pipelines and encouraging unsafe manual interventions.

Check `RUN` commands that invoke DNF (for example, `dnf install`, `dnf groupinstall`, `dnf localinstall`, `dnf reinstall`, and short forms such as `dnf in`/`dnf rei`) and require the `-y` or `--assumeyes` switch to be present. `RUN` lines invoking these commands without `-y`/`--assumeyes` will be flagged. Use a non-interactive invocation such as:

```dockerfile
RUN dnf -y install vim wget
```

## Compliant Code Examples
```dockerfile
FROM fedora:27
RUN set -uex && \
    dnf config-manager --set-enabled docker-ce-test && \
    dnf install -y docker-ce && \
    dnf clean all
```

```dockerfile
FROM fedora:27
RUN set -uex; \
    dnf config-manager --set-enabled docker-ce-test; \
    dnf install -y docker-ce; \
    dnf clean all

```

```dockerfile
FROM fedora:27
RUN microdnf install -y \
    openssl-libs-1:1.1.1k-6.el8_5.x86_64 \
    zlib-1.2.11-18.el8_5.x86_64 \
 && microdnf clean all

```
## Non-Compliant Code Examples
```dockerfile
FROM fedora:27
RUN set -uex; \
    dnf config-manager --set-enabled docker-ce-test; \
    dnf install docker-ce; \
    dnf clean all

FROM fedora:28
RUN set -uex
RUN dnf config-manager --set-enabled docker-ce-test
RUN dnf in docker-ce
RUN dnf clean all

```

```dockerfile
FROM fedora:27
RUN set -uex && \
    dnf config-manager --set-enabled docker-ce-test && \
    dnf install docker-ce && \
    dnf clean all

FROM fedora:28
RUN set -uex
RUN dnf config-manager --set-enabled docker-ce-test
RUN dnf in docker-ce
RUN dnf clean all
```