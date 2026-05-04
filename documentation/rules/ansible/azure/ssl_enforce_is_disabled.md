---
title: "SSL enforce disabled"
group_id: "Ansible / Azure"
meta:
  name: "azure/ssl_enforce_is_disabled"
  id: "ansible-azure-ssl-enforce-is-disabled"
  display_name: "SSL enforce disabled"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `ansible-azure-ssl-enforce-is-disabled`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_postgresqlserver_module.html#parameter-enforce_ssl)

### Description

PostgreSQL servers must enforce SSL connections to ensure client‑server traffic is encrypted and prevent credential exposure in transit. For Ansible playbooks using the `azure.azcollection.azure_rm_postgresqlserver` or `azure_rm_postgresqlserver` modules, the `enforce_ssl` parameter must be set to `true` (Ansible `yes`/true). Tasks that omit `enforce_ssl` (it defaults to `false`) or set it to `false` are flagged as insecure.

Secure configuration example:

```yaml
- name: Create PostgreSQL server with SSL enforced
  azure.azcollection.azure_rm_postgresqlserver:
    name: mypgserver
    resource_group: my-rg
    location: eastus
    enforce_ssl: yes
```

## Compliant Code Examples
```yaml
- name: Create (or update) PostgreSQL Server
  azure.azcollection.azure_rm_postgresqlserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_mb: 1024
    enforce_ssl: yes
    admin_username: cloudsa
    admin_password: password
- name: Create (or update) PostgreSQL Server2
  azure.azcollection.azure_rm_postgresqlserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_mb: 1024
    enforce_ssl: Yes
    admin_username: cloudsa
    admin_password: password
- name: Create (or update) PostgreSQL Server3
  azure.azcollection.azure_rm_postgresqlserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_mb: 1024
    enforce_ssl: true
    admin_username: cloudsa
    admin_password: password
- name: Create (or update) PostgreSQL Server4
  azure.azcollection.azure_rm_postgresqlserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_mb: 1024
    enforce_ssl: true
    admin_username: cloudsa
    admin_password: password
- name: Create (or update) PostgreSQL Server5
  azure.azcollection.azure_rm_postgresqlserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_mb: 1024
    enforce_ssl: yes
    admin_username: cloudsa
    admin_password: password
- name: Create (or update) PostgreSQL Server6
  azure.azcollection.azure_rm_postgresqlserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_mb: 1024
    enforce_ssl: Yes
    admin_username: cloudsa
    admin_password: password
- name: Create (or update) PostgreSQL Server7
  azure.azcollection.azure_rm_postgresqlserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_mb: 1024
    enforce_ssl: 'true'
    admin_username: cloudsa
    admin_password: password
- name: Create (or update) PostgreSQL Server8
  azure.azcollection.azure_rm_postgresqlserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_mb: 1024
    enforce_ssl: 'True'
    admin_username: cloudsa
    admin_password: password

```
## Non-Compliant Code Examples
```yaml
- name: Create (or update) PostgreSQL Server
  azure.azcollection.azure_rm_postgresqlserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_mb: 1024
    admin_username: cloudsa
    admin_password: password
- name: Create (or update) PostgreSQL Server2
  azure.azcollection.azure_rm_postgresqlserver:
    resource_group: myResourceGroup
    name: testserver
    sku:
      name: B_Gen5_1
      tier: Basic
    location: eastus
    storage_mb: 1024
    enforce_ssl: no
    admin_username: cloudsa
    admin_password: password

```