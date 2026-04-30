---
title: "SQL Server predictable Active Directory account name"
group_id: "Ansible / Azure"
meta:
  name: "azure/sql_server_predictable_active_directory_admin_account_name"
  id: "ansible-azure-sql-server-predictable-active-directory-account-name"
  display_name: "SQL Server predictable Active Directory account name"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `ansible-azure-sql-server-predictable-active-directory-account-name`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_adserviceprincipal_module.html)

### Description

Active Directory administrator accounts for Azure SQL Server must not use predictable or common names such as "admin" or "administrator." Predictable account names make privileged accounts easy to discover and enable targeted brute-force and credential-stuffing attacks.

In Ansible, verify the `azure.azcollection.azure_rm_adserviceprincipal` (or `azure_rm_adserviceprincipal`) task's `ad_user` property is defined, non-empty, and set to a non-predictable, unique name. This rule flags tasks where `ad_user` is missing or `null`, or where the value matches common predictable names (case-insensitive) such as `admin`, `administrator`, `sqladmin`, `root`, `user`, `azure_admin`, `azure_administrator`, or `guest`. Use a clear, non-guessable name for `ad_user`. For example:

```yaml
- name: Create AD service principal for Azure SQL admin
  azure.azcollection.azure_rm_adserviceprincipal:
    ad_user: "sqlsvc-prod-01"
    password: "{{ lookup('password', '/dev/null length=32') }}"
    state: present
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: create ad sp
  azure_rm_adserviceprincipal:
    display_name: my-sp
    app_id: '{{ app_id }}'
    state: present
    tenant: '{{ tenant_id }}'
    ad_user: unpredictableName

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: create ad sp
  azure_rm_adserviceprincipal:
    display_name: my-sp
    app_id: "{{ app_id }}"
    state: present
    tenant: "{{ tenant_id }}"
    ad_user: admin
- name: create ad sp2
  azure_rm_adserviceprincipal:
    display_name: my-sp2
    app_id: "{{ app_id2 }}"
    state: present
    tenant: "{{ tenant_id2 }}"
    ad_user: ""
- name: create ad sp3
  azure_rm_adserviceprincipal:
    display_name: my-sp3
    app_id: "{{ app_id3 }}"
    state: present
    tenant: "{{ tenant_id3 }}"
    ad_user:

```