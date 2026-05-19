---
title: "SQLServer ingress from any IP"
group_id: "Ansible / Azure"
meta:
  name: ""azure/sql_server_ingress_from_any_ip""
  id: "ansible-azure-sql-server-ingress-from-any-ip"
  display_name: "SQLServer ingress from any IP"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-azure-sql-server-ingress-from-any-ip{{< /copyable-code >}}

**Provider:** Azure

**Platform:** Ansible

**Severity:** Critical

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_sqlfirewallrule_module.html)

### Description

Allowing an Azure SQL firewall rule to accept connections from the entire internet (`start_ip_address` set to `0.0.0.0` and `end_ip_address` set to `255.255.255.255`) exposes database servers to unauthorized access and credential brute-force attacks.

This rule checks Ansible resources using the `azure.azcollection.azure_rm_sqlfirewallrule` (or `azure_rm_sqlfirewallrule`) module. Resources with `start_ip_address` set to `0.0.0.0` and `end_ip_address` set to `255.255.255.255` are flagged. Restrict firewall rules to specific client IPs or CIDR ranges, or use virtual network-based rules to limit access. 

Secure example with a single allowed IP:

```yaml
- name: Add SQL firewall rule for a specific IP
  azure.azcollection.azure_rm_sqlfirewallrule:
    resource_group: myResourceGroup
    server_name: my-sql-server
    name: allow-office-ip
    start_ip_address: 203.0.113.5
    end_ip_address: 203.0.113.5
    state: present
```

## Compliant Code Examples
```yaml
- name: Create (or update) Firewall Rule
  azure.azcollection.azure_rm_sqlfirewallrule:
    resource_group: myResourceGroup
    server_name: firewallrulecrudtest-6285
    name: firewallrulecrudtest-5370
    start_ip_address: 172.28.10.136
    end_ip_address: 172.28.10.138
- name: Create (or update) Firewall Rule2
  azure.azcollection.azure_rm_sqlfirewallrule:
    resource_group: myResourceGroup
    server_name: firewallrulecrudtest-6285
    name: firewallrulecrudtest-5370
    start_ip_address: 0.0.0.0
    end_ip_address: 0.0.0.3
- name: Create (or update) Firewall Rule3
  azure.azcollection.azure_rm_sqlfirewallrule:
    resource_group: myResourceGroup
    server_name: firewallrulecrudtest-6285
    name: firewallrulecrudtest-5370
    start_ip_address: 255.255.255.250
    end_ip_address: 255.255.255.255

```
## Non-Compliant Code Examples
```yaml
---
- name: Create (or update) Firewall Rule
  azure.azcollection.azure_rm_sqlfirewallrule:
    resource_group: myResourceGroup
    server_name: firewallrulecrudtest-6285
    name: firewallrulecrudtest-5370
    start_ip_address: 0.0.0.0
    end_ip_address: 255.255.255.255

```