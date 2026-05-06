---
title: "Redis cache allows non-SSL connections"
group_id: "Ansible / Azure"
meta:
  name: "azure/redis_cache_allows_non_ssl_connections"
  id: "869e7fb4-30f0-4bdb-b360-ad548f337f2f"
  display_name: "Redis cache allows non-SSL connections"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{</* copyable-code */>}}869e7fb4-30f0-4bdb-b360-ad548f337f2f{{</* copyable-code */>}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_rediscache_module.html)

### Description

Allowing non-SSL (plaintext) connections to Azure Cache for Redis exposes data in transit to interception and tampering. This can leak credentials and sensitive cached data or enable man-in-the-middle attacks.

For Ansible tasks using the `azure.azcollection.azure_rm_rediscache` or `azure_rm_rediscache` modules, the `enable_non_ssl_port` property must be set to `false` or omitted so only SSL/TLS connections are permitted. Resources with `enable_non_ssl_port: true` are flagged. Ensure clients connect over the TLS/SSL port (typically 6380) and validate certificates. 

Secure Ansible configuration example:

```yaml
- name: Create Redis Cache with TLS-only access
  azure.azcollection.azure_rm_rediscache:
    resource_group: my-rg
    name: my-redis
    location: eastus
    sku: name=Standard
    enable_non_ssl_port: false
```

## Compliant Code Examples
```yaml
- name: Non SSl Disallowed
  azure_rm_rediscache:
    resource_group: myResourceGroup
    name: myRedis
    enable_non_ssl_port: no
- name: Non SSl Undefined
  azure_rm_rediscache:
    resource_group: myResourceGroup
    name: myRedis

```
## Non-Compliant Code Examples
```yaml
- name: Non SSl Allowed
  azure_rm_rediscache:
      resource_group: myResourceGroup
      name: myRedis
      enable_non_ssl_port: yes

```