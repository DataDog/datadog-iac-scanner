---
title: "Firewall rule allows too many hosts to access Redis Cache"
group_id: "Ansible / Azure"
meta:
  name: "azure/firewall_rule_allows_too_many_hosts_to_access_redis_cache"
  id: "69f72007-502e-457b-bd2d-5012e31ac049"
  display_name: "Firewall rule allows too many hosts to access Redis Cache"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `69f72007-502e-457b-bd2d-5012e31ac049`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_rediscachefirewallrule_module.html)

### Description

Redis Cache firewall rules should restrict the IP address range to minimize attack surface and prevent broad network access that could allow unauthorized access or lateral movement.

In Ansible, tasks using `azure.azcollection.azure_rm_rediscachefirewallrule` or `azure_rm_rediscachefirewallrule` must set `start_ip_address` and `end_ip_address` so the numeric range covers at most 255 hosts. Any rule where the computed range (`abs(end - start)`) is greater than 255 is flagged.

Resources missing these properties or defining overly large ranges should be tightened to a single IP or a narrow range. Alternatively, replace them with network-level controls such as private endpoints or service endpoints to limit access.

Secure example with a small allowed range:

```yaml
- name: Allow small Redis access range
  azure.azcollection.azure_rm_rediscachefirewallrule:
    resource_group: my-rg
    name: my-redis
    start_ip_address: 10.0.0.10
    end_ip_address: 10.0.0.20
```

## Compliant Code Examples
```yaml
- name: reduced_hosts
  azure_rm_rediscachefirewallrule:
    resource_group: myResourceGroup
    cache_name: myRedisCache
    name: myRule
    start_ip_address: 192.168.1.1
    end_ip_address: 192.168.1.4

```
## Non-Compliant Code Examples
```yaml
- name: too_many_hosts
  azure_rm_rediscachefirewallrule:
      resource_group: myResourceGroup
      cache_name: myRedisCache
      name: myRule
      start_ip_address: 192.168.1.1
      end_ip_address: 192.169.1.4

```