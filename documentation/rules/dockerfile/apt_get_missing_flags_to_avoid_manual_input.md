---
title: "apt-get missing flags to avoid manual input"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/apt_get_missing_flags_to_avoid_manual_input"
  id: "77783205-c4ca-4f80-bb80-c777f267c547"
  display_name: "apt-get missing flags to avoid manual input"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** `77783205-c4ca-4f80-bb80-c777f267c547`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#run)

### Description

`apt-get install` commands in Dockerfile `RUN` instructions must be non-interactive to avoid build hangs and inconsistent or improperly configured images. Interactive prompts can stall CI/CD pipelines or lead to images being produced with unintended defaults.

This rule inspects Dockerfile `RUN` instructions and requires that any command invoking `apt-get install` includes non-interactive flags such as `-y`, `--yes`, `--assume-yes`, `-qq`, `-q=2`, `-qy` or an equivalent use of quiet flags to suppress prompts. `RUN` lines missing these flags will be flagged.

For reliable automated builds, also consider setting `DEBIAN_FRONTEND=noninteractive` in the same `RUN` line and using `--no-install-recommends` to reduce prompts and avoid installing extra packages.

Secure example:

```Dockerfile
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl
```

## Compliant Code Examples
```dockerfile
FROM node:12
RUN apt-get --assume-yes install apt-utils
RUN ["sudo", "apt-get", "--assume-yes", "install", "apt-utils"] 

```

```dockerfile
FROM node:12
RUN apt-get -q -q install sl
RUN ["apt-get", "-q", "-q", "apt-utils"]

```

```dockerfile
FROM node:12
RUN sudo apt-get -y install apt-utils
RUN sudo apt-get -qy install git gcc
RUN ["sudo", "apt-get", "-y", "install", "apt-utils"]

```
## Non-Compliant Code Examples
```dockerfile
FROM node:12
RUN ["sudo", "apt-get", "--quiet", "install", "apt-utils"] 
RUN sudo apt-get --quiet install apt-utils
```

```dockerfile
FROM node:12
RUN sudo apt-get install python=2.7
RUN sudo apt-get install apt-utils
RUN ["sudo", "apt-get", "install", "apt-utils"]

```

```dockerfile
FROM node:12
RUN sudo apt-get -q install sl
RUN ["apt-get", "-q", "install", "apt-utils"] 
```