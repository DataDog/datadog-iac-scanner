---
title: "PostgreSQL log disconnections not set"
group_id: "Ansible / Azure"
meta:
  name: ""azure/postgresql_log_disconnections_not_set""
  id: "ansible-azure-postgresql-log-disconnections-not-set"
  display_name: "PostgreSQL log disconnections not set"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-azure-postgresql-log-disconnections-not-set{{< /copyable-code >}}

**Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_postgresqlconfiguration_module.html)

### Description

Enabling the PostgreSQL server parameter `log_disconnections` ensures the server records client connection termination events. This is important for detecting abnormal connection patterns, troubleshooting connectivity issues, and supporting forensic investigations.

For Ansible, the `azure.azcollection.azure_rm_postgresqlconfiguration` (or legacy `azure_rm_postgresqlconfiguration`) resource must have `name: log_disconnections` and `value: ON` (value compared case-insensitively). Resources where `name` is `log_disconnections` but `value` is missing, not a string, or not set to `ON` are flagged as insecure.

Secure Ansible configuration example:

```yaml
- name: Enable PostgreSQL log_disconnections
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: my-rg
    server_name: my-pg-server
    name: log_disconnections
    value: ON
```

## Compliant Code Examples
```yaml
- name: Update PostgreSQL Server setting
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_disconnections
    value: on
- name: Update PostgreSQL Server setting2
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_disconnections
    value: On
- name: Update PostgreSQL Server setting3
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_disconnections
    value: ON
- name: Update PostgreSQL Server setting4
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_disconnections
    value: on
- name: Update PostgreSQL Server setting5
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_disconnections
    value: On
- name: Update PostgreSQL Server setting6
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_disconnections
    value: ON

```
## Non-Compliant Code Examples
```yaml
---
- name: Update PostgreSQL Server setting
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_disconnections
    value: off
- name: Update PostgreSQL Server setting2
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_disconnections
    value: Off
- name: Update PostgreSQL Server setting3
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_disconnections
    value: OFF
- name: Update PostgreSQL Server setting4
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_disconnections
    value: "off"
- name: Update PostgreSQL Server setting5
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_disconnections
    value: "Off"
- name: Update PostgreSQL Server setting6
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_disconnections
    value: "OFF"

```