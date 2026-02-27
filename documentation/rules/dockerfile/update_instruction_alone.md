---
title: "Package update without install in same RUN"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/update_instruction_alone"
  id: "9bae49be-0aa3-4de5-bab2-4c3a069e40cd"
  display_name: "Package update without install in same RUN"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `9bae49be-0aa3-4de5-bab2-4c3a069e40cd`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run)

### Description

Separating a package index update from the package installation across multiple Dockerfile `RUN` instructions can cause builds to use cached layers and install packages from stale indexes. This increases the risk of including outdated or vulnerable package versions in the image.

This check examines Dockerfile `RUN` commands (resources where `Cmd == "run"` and `Value` contains the command string) and verifies that when a package-manager updater is invoked (examples: `apt-get update`, `apt update`, `apk update`, `yum update`, `dnf update`, `zypper refresh`, `pacman -Syu`) it is followed in the same `RUN` statement by the corresponding installer command (for example, `apt-get install`/`apt install`, `apk add`, `yum install`, `dnf install`, `zypper install`, and `pacman -S`). Resources that run an update without an install in the same `RUN`, or that place the install in a later `RUN` instruction, will be flagged. 

Secure examples that combine update and install in one `RUN`:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends package1 package2 && rm -rf /var/lib/apt/lists/*
```

```dockerfile
RUN apk update && apk add --no-cache package1 package2
```

## Compliant Code Examples
```dockerfile
FROM ubuntu:18.04
RUN apt-get update && apt-get install -y --no-install-recommends mysql-client \
    && rm -rf /var/lib/apt/lists/*
RUN apk update
ENTRYPOINT ["mysql"]

```

```dockerfile
FROM centos:latest
RUN yum update && yum install nginx

CMD ["nginx", "-g", "daemon off;"]
```

```dockerfile
FROM ubuntu:18.04
RUN apt-get update && apt-get install -y netcat \
    apt-get update && apt-get install -y supervisor
ENTRYPOINT ["mysql"]

```
## Non-Compliant Code Examples
```dockerfile
FROM fedora:latest
RUN dnf update
RUN dnf install nginx

CMD ["nginx", "-g", "daemon off;"]
```

```dockerfile
FROM opensuse:latest
RUN zypper refresh
RUN zypper install nginx

CMD ["nginx", "-g", "daemon off;"]
```

```dockerfile
FROM ubuntu:18.04
RUN apt-get update
RUN apt-get install -y --no-install-recommends mysql-client \
    && rm -rf /var/lib/apt/lists/*
RUN apk update
ENTRYPOINT ["mysql"]
```