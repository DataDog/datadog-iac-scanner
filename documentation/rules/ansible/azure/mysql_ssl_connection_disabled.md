---
title: "MySQL SSL connection disabled"
group_id: "Ansible / Azure"
meta:
  name: "azure/mysql_ssl_connection_disabled"
  id: "2a901825-0f3b-4655-a0fe-e0470e50f8e6"
  display_name: "MySQL SSL connection disabled"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}2a901825-0f3b-4655-a0fe-e0470e50f8e6{{< /copyable-code >}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_mysqlserver_module.html)

### Description

MySQL servers must enforce SSL/TLS connections to protect data in transit and prevent interception or man-in-the-middle attacks. For Ansible tasks using the `azure.azcollection.azure_rm_mysqlserver` or `azure_rm_mysqlserver` modules, the `enforce_ssl` property must be defined and set to `true` so the server requires TLS for client connections.

Resources missing this property or with `enforce_ssl: false` (the default) are flagged. Use Ansible boolean values such as `true` or `yes` to enable this setting. The rule treats Ansible truthy values as valid.

```yaml
- name: Create Azure MySQL server with SSL enforced
  azure.azcollection.azure_rm_mysqlserver:
    name: my-mysql-server
    resource_group: my-rg
    location: eastus
    sku: B_Gen5_1
    version: "5.7"
    administrator_login: adminuser
    administrator_login_password: "{{ mysql_password }}"
    enforce_ssl: true
```

## Compliant Code Examples
```yaml
- name: Create (or update) MySQL Server
  azure.azcollection.azure_rm_mysqlserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_mb: 1024
    enforce_ssl: true
    version: 5.6
    admin_username: cloudsa
    admin_password: password

```
## Non-Compliant Code Examples
```yaml
---
- name: Create (or update) MySQL Server
  azure.azcollection.azure_rm_mysqlserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_mb: 1024
    version: 5.6
    admin_username: cloudsa
    admin_password: password
- name: Create (or update) MySQL Server2
  azure.azcollection.azure_rm_mysqlserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_mb: 1024
    enforce_ssl: false
    version: 5.6
    admin_username: cloudsa
    admin_password: password

```