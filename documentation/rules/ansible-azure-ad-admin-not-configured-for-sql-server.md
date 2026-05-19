---
title: "AD admin not configured for SQL server"
group_id: "Ansible / Azure"
meta:
  name: "azure/ad_admin_not_configured_for_sql_server"
  id: "ansible-azure-ad-admin-not-configured-for-sql-server"
  display_name: "AD admin not configured for SQL server"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-azure-ad-admin-not-configured-for-sql-server{{< /copyable-code >}}

**Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_sqlserver_module.html#parameter-ad_user)

### Description

SQL servers should have an Active Directory administrator configured to enforce centralized identity, stronger authentication, and auditable access controls. Relying solely on SQL authentication increases the attack surface and makes access management and auditing more difficult. For Ansible, tasks using the `azure.azcollection.azure_rm_sqlserver` or `azure_rm_sqlserver` module must define the `ad_user` property and set it to a valid Azure AD principal (for example, a user UPN or objectId). Resources missing `ad_user` or with it empty or undefined are flagged.

Secure example:

```
- name: Create Azure SQL Server with AD admin
  azure.azcollection.azure_rm_sqlserver:
    name: my-sql-server
    resource_group: my-rg
    location: eastus
    ad_user: "adminuser@contoso.com"
    admin_password: "secure-password"
```

## Compliant Code Examples
```yaml
- name: Create (or update) SQL Server
  azure_rm_sqlserver:
    resource_group: myResourceGroup
    name: server_name
    location: westus
    admin_username: mylogin
    admin_password: Testpasswordxyz12!
    ad_user: sqladmin

```
## Non-Compliant Code Examples
```yaml
---
- name: Create (or update) SQL Server
  azure_rm_sqlserver:
    resource_group: myResourceGroup
    name: server_name
    location: westus
    admin_username: mylogin
    admin_password: Testpasswordxyz12!

```