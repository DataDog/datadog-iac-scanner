---
title: "Redis entirely accessible"
group_id: "Ansible / Azure"
meta:
  name: "azure/redis_entirely_accessible"
  id: "0d0c12b9-edce-4510-9065-13f6a758750c"
  display_name: "Redis entirely accessible"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `0d0c12b9-edce-4510-9065-13f6a758750c`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Critical

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_rediscachefirewallrule_module.html#parameter-start_ip_address)

### Description

Allowing a Redis cache firewall rule to use `0.0.0.0` for both start and end addresses grants unrestricted internet access to the cache, exposing it to unauthorized access, data exposure, and potential remote exploitation.

For Ansible tasks using `azure.azcollection.azure_rm_rediscachefirewallrule` or `azure_rm_rediscachefirewallrule`, the `start_ip_address` and `end_ip_address` properties must be defined and must not be set to `"0.0.0.0"`. Specify a limited IP range or a single trusted IP address (set both start and end to the same IP for a single host). Resources where both `start_ip_address` and `end_ip_address` equal `"0.0.0.0"` are flagged. Restrict access to known management IPs, use VNet integration, or Azure service endpoints to avoid exposing Redis to the public internet.

Secure example limiting access to a single admin IP:

```yaml
- name: Allow Redis access from admin IP
  azure.azcollection.azure_rm_rediscachefirewallrule:
    resource_group: my-resource-group
    name: my-redis-cache
    start_ip_address: 203.0.113.5
    end_ip_address: 203.0.113.5
```

## Compliant Code Examples
```yaml
- name: Create a Firewall rule for Azure Cache for Redis
  azure_rm_rediscachefirewallrule:
    resource_group: myResourceGroup
    cache_name: myRedisCache
    name: myRule
    start_ip_address: 192.168.1.1
    end_ip_address: 192.168.1.4

```
## Non-Compliant Code Examples
```yaml
---
- name: Create a Firewall rule for Azure Cache for Redis
  azure_rm_rediscachefirewallrule:
      resource_group: myResourceGroup
      cache_name: myRedisCache
      name: myRule
      start_ip_address: 0.0.0.0
      end_ip_address: 0.0.0.0

```