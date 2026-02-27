---
title: "yum install without version"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/yum_install_without_version"
  id: "6452c424-1d92-4deb-bb18-a03e95d579c4"
  display_name: "yum install without version"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "MEDIUM"
  category: "Supply-Chain"
---
## Metadata

**Id:** `6452c424-1d92-4deb-bb18-a03e95d579c4`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Medium

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run)

### Description

Dockerfile `RUN` commands that use `yum install` must specify explicit package versions to ensure build reproducibility and reduce the risk of unintentionally installing newer, unvetted, or vulnerable package releases.

This rule inspects Dockerfile `RUN` instructions that invoke `yum install` and flags package arguments that are plain names without a version specifier. Each package should include an explicit version (for example, `pkg-1.2.3` or `pkg=1.2.3`).

Both single-string `RUN` commands and tokenized `RUN` forms are checked. Command flags and options (for example, `-y`, `--enablerepo`) are ignored, and only tokens beginning with letters are validated. Resources missing a version for any package will be flagged.

Secure example:

```dockerfile
FROM centos:7
RUN yum install -y httpd-2.4.6-90.el7.centos mod_ssl-2.4.6-90.el7.centos
```

## Compliant Code Examples
```dockerfile
FROM opensuse/leap:15.2
RUN yum install -y httpd-2.24.2 && yum clean all
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1


FROM opensuse/leap:15.3
ENV RETHINKDB_PACKAGE_VERSION 2.4.0~0trusty
RUN yum install -y rethinkdb-$RETHINKDB_PACKAGE_VERSION && yum clean all

```
## Non-Compliant Code Examples
```dockerfile
FROM opensuse/leap:15.2
RUN yum install -y httpd && yum clean all
RUN ["yum", "install", "httpd"]
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1

```