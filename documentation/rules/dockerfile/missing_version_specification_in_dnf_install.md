---
title: "Missing version specification in dnf install"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/missing_version_specification_in_dnf_install"
  id: "93d88cf7-f078-46a8-8ddc-178e03aeacf1"
  display_name: "Missing version specification in dnf install"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Supply-Chain"
---
## Metadata

**Id:** `93d88cf7-f078-46a8-8ddc-178e03aeacf1`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)

### Description

Dockerfile `RUN` commands that install packages with DNF must pin package versions to ensure reproducible builds and avoid unintended upgrades or supply-chain changes that can introduce vulnerable or incompatible packages.

This rule scans Dockerfile `RUN` instructions invoking `dnf install` and flags package operands that do not include an explicit version suffix. Packages should be specified with a concrete version (for example, `package-1.2.3` or `package-1.2.3-1`).

Resources with unversioned package names in the `RUN` line will be flagged. Fix by pinning versions in the install command or by using a locked repository snapshot or package manifest for reproducible, auditable builds.

Secure example:

```dockerfile
RUN dnf -y install openssl-1.1.1k-1.el8 curl-7.61.1-12.el8 && dnf clean all
```

## Compliant Code Examples
```dockerfile
FROM fedora:latest
RUN dnf -y update && dnf -y install httpd-2.24.2 && dnf clean all
RUN ["dnf", "install", "httpd-2.24.2"]
COPY index.html /var/www/html/index.html
EXPOSE 80
ENTRYPOINT /usr/sbin/httpd -DFOREGROUND

```
## Non-Compliant Code Examples
```dockerfile
FROM fedora:latest
RUN dnf -y update && dnf -y install httpd && dnf clean all
RUN ["dnf", "install", "httpd"]
COPY index.html /var/www/html/index.html
EXPOSE 80
ENTRYPOINT /usr/sbin/httpd -DFOREGROUND

```