---
title: "SQL Server Predictable Active Directory Account Name"
group_id: "Ansible / Azure"
meta:
  name: "azure/sql_server_predictable_active_directory_admin_account_name"
  id: "530e8291-2f22-4bab-b7ea-306f1bc2a308"
  display_name: "SQL Server Predictable Active Directory Account Name"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `530e8291-2f22-4bab-b7ea-306f1bc2a308`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_adserviceprincipal_module.html)

### Description

Active Directory administrator accounts for Azure SQL Server must not use predictable or common names (for example, "admin" or "administrator"), because predictable account names make privileged accounts easy to discover and enable targeted brute-force and credential-stuffing attacks. In Ansible, verify the `azure.azcollection.azure_ad_serviceprincipal` (or `azure_ad_serviceprincipal`) task's `ad_user` property is defined and non-empty and set to a non-predictable, unique name. This rule flags tasks where `ad_user` is missing or null, or where the case-insensitive value matches common predictable names such as `admin`, `administrator`, `sqladmin`, `root`, `user`, `azure_admin`, `azure_administrator`, or `guest`. Use a clear, non-guessable name for `ad_user`, for example:

```yaml
- name: Create AD service principal for Azure SQL admin
  azure.azcollection.azure_ad_serviceprincipal:
    ad_user: "sqlsvc-prod-01"
    password: "{{ lookup('password', '/dev/null length=32') }}"
    state: present
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: create ad sp
  azure_ad_serviceprincipal:
    app_id: '{{ app_id }}'
    state: present
    tenant: '{{ tenant_id }}'
    ad_user: unpredictableName

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: create ad sp
  azure_ad_serviceprincipal:
    app_id: "{{ app_id }}"
    state: present
    tenant: "{{ tenant_id }}"
    ad_user: admin
- name: create ad sp2
  azure_ad_serviceprincipal:
    app_id: "{{ app_id2 }}"
    state: present
    tenant: "{{ tenant_id2 }}"
    ad_user: ""
- name: create ad sp3
  azure_ad_serviceprincipal:
    app_id: "{{ app_id3 }}"
    state: present
    tenant: "{{ tenant_id3 }}"
    ad_user:

```