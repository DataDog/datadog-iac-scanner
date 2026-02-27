---
title: "Zypper install without explicit package version"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/zypper_install_without_version"
  id: "562952e4-0348-4dea-9826-44f3a2c6117b"
  display_name: "Zypper install without explicit package version"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** `562952e4-0348-4dea-9826-44f3a2c6117b`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run)

### Description

When using zypper to install packages in a Dockerfile, each package should include an explicit version to ensure reproducible builds and avoid unintentionally pulling newer package releases that could introduce vulnerabilities or break functionality.

This rule inspects Dockerfile `RUN` instructions that invoke `zypper install` or `zypper in` (both shell-form and exec-form) and flags package arguments that are bare names without a version component. Resources missing a version, for example, `curl` instead of `curl=7.79.1` will be flagged. Specify the version inline using the repository-appropriate syntax or use a package pin/lock mechanism to fix the exact package release.

Secure example:

```Dockerfile
RUN zypper install -y curl=7.79.1 libxml2=2.9.10
```

## Compliant Code Examples
```dockerfile
FROM opensuse/leap:15.2
RUN zypper install -y httpd=2.4.46 && zypper clean
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1

```
## Non-Compliant Code Examples
```dockerfile
FROM opensuse/leap:15.2
RUN zypper install -y httpd && zypper clean
RUN ["zypper", "install", "http"]
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1

```