---
title: "Run utilities and POSIX commands"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/run_utilities_and_posix_commands"
  id: "9b6b0f38-92a2-41f9-b881-3a1083d99f1b"
  display_name: "Run utilities and POSIX commands"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** `9b6b0f38-92a2-41f9-b881-3a1083d99f1b`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#run)

### Description

`RUN` instructions in Dockerfiles must not invoke interactive editors or host-level utilities (for example, ps, shutdown, service, free, top, kill, mount, ifconfig, nano, and vim). These tools are unnecessary in image builds, can attempt to access or manipulate host/system state, and may indicate insecure usage patterns that increase the risk of container escape or unstable images.

This rule inspects Dockerfile `RUN` commands and flags any `RUN` whose command string (each segment split on `&&`) contains one of the listed command names. Segments that include the substring `install` (for example, package manager install commands) are excluded and will not be flagged. Remediate by removing interactive or service-management invocations from build steps, performing process/service control at runtime or on the host, or installing required utilities non-interactively during build without executing them.

Secure example installing a utility non-interactively:

```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends curl
```

## Compliant Code Examples
```dockerfile
FROM ubuntu
RUN apt-get update && apt-get install -y x11vnc xvfb firefox
RUN mkdir ~/.vnc
RUN x11vnc -storepasswd 1234 ~/.vnc/passwd
RUN bash -c 'echo "firefox" >> /.bashrc'
RUN apt-get install nano vim
EXPOSE 5900
CMD    ["x11vnc", "-forever", "-usepw", "-create"]

```
## Non-Compliant Code Examples
```dockerfile
FROM golang:1.12.0-stretch
WORKDIR /go
COPY . /go
RUN top
RUN ["ps", "-d"]
CMD ["go", "run", "main.go"]

```