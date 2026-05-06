---
title: "Redis publicly accessible"
group_id: "Ansible / Azure"
meta:
  name: "azure/redis_publicly_accessible"
  id: "0632d0db-9190-450a-8bb3-c283bffea445"
  display_name: "Redis publicly accessible"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{</* copyable-code */>}}0632d0db-9190-450a-8bb3-c283bffea445{{</* copyable-code */>}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Critical

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_rediscachefirewallrule_module.html#parameter-start_ip_address)

### Description

Allowing public IP ranges in Azure Redis Cache firewall rules exposes the cache to unauthorized internet access, increasing the risk of data exfiltration and lateral movement.

The Ansible modules `azure.azcollection.azure_rm_rediscachefirewallrule` and `azure_rm_rediscachefirewallrule` must set `start_ip_address` and `end_ip_address` to private IP ranges (RFC1918). Tasks missing these properties or specifying non-private or public IPs are flagged.

If access should be limited to Azure resources, prefer virtual network rules or service endpoints instead of broad IP ranges, and ensure any IP range only includes trusted internal addresses.

Secure configuration example:

```yaml
- name: allow internal subnet to access redis
  azure.azcollection.azure_rm_rediscachefirewallrule:
    name: allow-internal
    resource_group: my-rg
    redis_name: my-redis
    start_ip_address: 10.0.0.1
    end_ip_address: 10.0.0.255
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
      start_ip_address: 1.2.3.4
      end_ip_address: 2.3.4.5

```