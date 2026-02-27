---
title: "apt-get not avoiding additional packages"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/apt_get_not_avoiding_additional_packages"
  id: "7384dfb2-fcd1-4fbf-91cd-6c44c318c33c"
  display_name: "apt-get not avoiding additional packages"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** `7384dfb2-fcd1-4fbf-91cd-6c44c318c33c`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#run)

### Description

Dockerfile `RUN` instructions that invoke `apt-get install` should disable installation of recommended packages to reduce the image attack surface. Avoiding unnecessary package bloat decreases maintenance burden and potential vulnerabilities.

This check looks at `RUN` commands (both shell/string form and exec/array form) that call `apt-get` with `install` and requires either the `--no-install-recommends` option or the APT configuration `apt::install-recommends` set to `false`. Resources where the install command does not include `--no-install-recommends` and does not set `apt::install-recommends` to `false` will be flagged. 

Secure examples:

```dockerfile
# shell form
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*

# exec/array form
RUN ["apt-get", "update"]
RUN ["apt-get", "install", "-y", "--no-install-recommends", "ca-certificates", "curl"]
```

## Compliant Code Examples
```dockerfile
FROM node:12
RUN apt-get --no-install-recommends install apt-utils
RUN ["apt-get", "apt::install-recommends=false", "install", "apt-utils"]


```
## Non-Compliant Code Examples
```dockerfile
FROM node:12
RUN apt-get install apt-utils
RUN ["apt-get", "install", "apt-utils"]
```