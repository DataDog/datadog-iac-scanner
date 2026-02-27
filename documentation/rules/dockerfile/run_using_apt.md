---
title: "Run using apt"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/run_using_apt"
  id: "b84a0b47-2e99-4c9f-8933-98bcabe2b94d"
  display_name: "Run using apt"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** `b84a0b47-2e99-4c9f-8933-98bcabe2b94d`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run)

### Description

Using the interactive `apt` front-end in Dockerfile `RUN` instructions is discouraged because its user-facing behavior can change between versions and it may prompt for input during non-interactive image builds. This can cause build failures or incomplete/incorrect package installations that leave images outdated or inconsistent.

This rule flags Dockerfile `RUN` commands that invoke the token `apt ` (for example `RUN apt ...`) and instead requires using scripting-friendly tools such as `apt-get` and `apt-cache`. Replace `apt` with `apt-get`/`apt-cache`, run `apt-get update` before installs, use non-interactive and affirmative flags (for example, `-y --no-install-recommends`), and clean apt caches to reduce image size and avoid stale state. 

Secure example:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends <package> && rm -rf /var/lib/apt/lists/*
```

## Compliant Code Examples
```dockerfile
FROM busybox:1.0
RUN apt-get install curl
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1 

```
## Non-Compliant Code Examples
```dockerfile
FROM busybox:1.0
RUN apt install curl
HEALTHCHECK CMD curl --fail http://localhost:3000 || exit 1 

```