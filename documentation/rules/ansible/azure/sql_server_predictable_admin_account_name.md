---
title: "SQL Server predictable admin account name"
group_id: "Ansible / Azure"
meta:
  name: "azure/sql_server_predictable_admin_account_name"
  id: "ansible-azure-sql-server-predictable-admin-account-name"
  display_name: "SQL Server predictable admin account name"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `ansible-azure-sql-server-predictable-admin-account-name`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_sqlserver_module.html)

### Description

Admin usernames for Azure SQL Server must not be empty or use predictable names. Predictable account names (for example, "admin" or "administrator") make it significantly easier for attackers to perform brute-force, credential-stuffing, and targeted authentication attacks.

For Ansible resources using `azure.azcollection.azure_rm_sqlserver` or `azure_rm_sqlserver`, the `admin_username` property must be defined as a non-empty string. It must not be one of the following predictable names: `admin`, `administrator`, `root`, `user`, `azure_admin`, `azure_administrator`, or `guest`.

Tasks that omit `admin_username`, set it to an empty value, or use any of the predictable names (checked case-insensitively) are flagged as insecure. 

Secure example:

```yaml
- name: Create Azure SQL Server
  azure.azcollection.azure_rm_sqlserver:
    name: my-sql-server
    resource_group: my-rg
    location: eastus
    admin_username: dbadmin01
    admin_password: "{{ sql_admin_password }}"
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: Create (or update) SQL Server
  azure_rm_sqlserver:
    resource_group: myResourceGroup
    name: server_name
    location: westus
    admin_username: mylogin
    admin_password: Testpasswordxyz12!

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: Create (or update) SQL Server1
  azure_rm_sqlserver:
    resource_group: myResourceGroup
    name: server_name1
    location: westus
    admin_username: ""
    admin_password: Testpasswordxyz12!
- name: Create (or update) SQL Server2
  azure_rm_sqlserver:
    resource_group: myResourceGroup
    name: server_name2
    location: westus
    admin_username:
    admin_password: Testpasswordxyz12!
- name: Create (or update) SQL Server3
  azure_rm_sqlserver:
    resource_group: myResourceGroup
    name: server_name3
    location: westus
    admin_username: admin
    admin_password: Testpasswordxyz12!

```