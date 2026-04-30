---
title: "Unrestricted SQL Server access"
group_id: "Ansible / Azure"
meta:
  name: "azure/unrestricted_sql_server_acess"
  id: "ansible-azure-unrestricted-sql-server-access"
  display_name: "Unrestricted SQL Server access"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ansible-azure-unrestricted-sql-server-access`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Critical

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_sqlfirewallrule_module.html)

### Description

Allowing large IP ranges in Azure SQL firewall rules broadens the database attack surface and increases the risk of unauthorized access, brute-force attempts, and data exposure. Firewall rules should grant the minimal address range required.

For Ansible tasks using `azure_rm_sqlfirewallrule` or `azure.azcollection.azure_rm_sqlfirewallrule`, ensure the `start_ip_address` and `end_ip_address` properties are defined and that the numeric difference between them is less than 256 (that is, a single IP or up to 255 addresses). Tasks that omit these properties, set either address to `0.0.0.0`, or specify a range with difference >= 256 are flagged as insecure.

Secure configuration example:

```yaml
- name: Allow single client IP to Azure SQL firewall
  azure.azcollection.azure_rm_sqlfirewallrule:
    resource_group: my-rg
    server_name: my-sql-server
    name: allow-client
    start_ip_address: 203.0.113.45
    end_ip_address: 203.0.113.45
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: Create (or update) Firewall Rule
  azure_rm_sqlfirewallrule:
    resource_group: myResourceGroup
    server_name: firewallrulecrudtest-6285
    name: firewallrulecrudtest-5370
    start_ip_address: 172.28.10.136
    end_ip_address: 172.28.10.138

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: Create (or update) Firewall Rule1
  azure_rm_sqlfirewallrule:
    resource_group: myResourceGroup1
    server_name: firewallrulecrudtest-6285
    name: firewallrulecrudtest-5370
    start_ip_address: 0.0.0.0
    end_ip_address: 172.28.11.138
- name: Create (or update) Firewall Rule2
  azure_rm_sqlfirewallrule:
    resource_group: myResourceGroup2
    server_name: firewallrulecrudtest-6285
    name: firewallrulecrudtest-5370
    start_ip_address: 172.28.10.136
    end_ip_address: 172.28.11.138

```