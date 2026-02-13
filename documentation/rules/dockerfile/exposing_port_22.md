---
title: "Exposing port 22 (SSH)"
group_id: "Dockerfile / Dockerfile"
meta:
  name: "dockerfile/exposing_port_22"
  id: "5907595b-5b6d-4142-b173-dbb0e73fbff8"
  display_name: "Exposing port 22 (SSH)"
  cloud_provider: "Dockerfile"
  platform: "Dockerfile"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `5907595b-5b6d-4142-b173-dbb0e73fbff8`

**Cloud Provider:** Dockerfile

**Platform:** Dockerfile

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://sysdig.com/blog/dockerfile-best-practices/)

### Description

Exposing SSH (port 22) from a container image creates an unnecessary remote access surface that enables brute-force attacks, credential theft, and lateral movement if the container or host is compromised. This rule checks Dockerfiles for `EXPOSE` instructions and flags any `EXPOSE` entry that includes port `22`.

Remove port `22` from `EXPOSE` directives and rely on container runtime access methods (for example, `docker exec` or `kubectl exec`), a bastion host, or an ephemeral, tightly-controlled SSH gateway with network restrictions and strong authentication when interactive access is required.

Secure example without SSH exposed:

```dockerfile
EXPOSE 8080
```

## Compliant Code Examples
```dockerfile
FROM gliderlabs/alpine:3.3
RUN apk --no-cache add nginx
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

```
## Non-Compliant Code Examples
```dockerfile
FROM gliderlabs/alpine:3.3
RUN apk --no-cache add nginx
EXPOSE 3000 80 443 22
CMD ["nginx", "-g", "daemon off;"]

```