---
title: "UNIX ports out of range"
group_id: "Dockerfile"
meta:
  name: "unix_ports_out_of_range"
  id: "dockerfile-unix-ports-out-of-range"
  display_name: "UNIX ports out of range"
  cloud_provider: ""
  platform: "Dockerfile"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}dockerfile-unix-ports-out-of-range{{< /copyable-code >}}

**Platform:** Dockerfile

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.docker.com/engine/reference/builder/#expose)

### Description

Dockerfile `EXPOSE` instructions that specify port numbers outside the valid TCP/UDP range (0–65535) are misconfigurations that can cause build or runtime errors and may lead to unintended network exposure or incorrect port mappings.

This rule inspects Dockerfile `EXPOSE` commands and requires the numeric port value (the portion before any `/protocol` suffix) to be an integer between 0 and 65535 inclusive. The policy flags `EXPOSE` entries where the parsed port number is greater than 65535. Ensure you declare ports as numeric values within the valid range. For example:

```
EXPOSE 80
EXPOSE 8080/tcp
```

## Compliant Code Examples
```dockerfile
FROM gliderlabs/alpine:3.3
RUN apk --no-cache add nginx
EXPOSE 3000 80 443 22
CMD ["nginx", "-g", "daemon off;"]
```
## Non-Compliant Code Examples
```dockerfile
FROM gliderlabs/alpine:3.3
RUN apk --no-cache add nginx
EXPOSE 65536/tcp 80 443 22
CMD ["nginx", "-g", "daemon off;"]
```