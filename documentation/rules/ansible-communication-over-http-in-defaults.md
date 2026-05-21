---
title: "Communication over HTTP in defaults"
group_id: "Ansible"
meta:
  name: "communication_over_http_in_defaults"
  id: "ansible-communication-over-http-in-defaults"
  display_name: "Communication over HTTP in defaults"
  cloud_provider: ""
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-communication-over-http-in-defaults{{< /copyable-code >}}

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/plugins/httpapi.html)

### Description

Galaxy `server` URLs must use HTTPS to protect the confidentiality and integrity of downloaded roles and any credentials exchanged. Using plain HTTP exposes downloads and authentication data to interception or tampering.

In Ansible configuration documents, this is the `groups.galaxy.server` property, which must begin with `https://` instead of `http://`. Resources with a missing `server` property or a value that starts with `http://` are flagged. Ensure the HTTPS endpoint presents a valid TLS certificate and do not disable certificate verification.

Secure configuration example:

```yaml
groups:
  galaxy:
    server: "https://galaxy.example.com"
```

## Compliant Code Examples
```ini
[galaxy]
cache_dir=~/.ansible/galaxy_cache
ignore_certs=False
role_skeleton_ignore=^.git$, ^.*/.git_keep$
server=https://galaxy.ansible.com
```
## Non-Compliant Code Examples
```ini
[galaxy]
cache_dir=~/.ansible/galaxy_cache
ignore_certs=False
role_skeleton_ignore=^.git$, ^.*/.git_keep$
server=http://galaxy.ansible.com
```