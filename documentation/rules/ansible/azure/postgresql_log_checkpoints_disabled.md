---
title: "PostgreSQL log checkpoints disabled"
group_id: "Ansible / Azure"
meta:
  name: "azure/postgresql_log_checkpoints_disabled"
  id: "ansible-azure-postgresql-log-checkpoints-disabled"
  display_name: "PostgreSQL log checkpoints disabled"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `ansible-azure-postgresql-log-checkpoints-disabled`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_postgresqlconfiguration_module.html)

### Description

PostgreSQL's `log_checkpoints` should be enabled to record checkpoint activity. This improves visibility into I/O behavior and aids detection and troubleshooting of performance or recovery issues.

In Ansible Azure PostgreSQL configuration resources (`azure.azcollection.azure_rm_postgresqlconfiguration` or `azure_rm_postgresqlconfiguration`), when the `name` property is `log_checkpoints`, the `value` property must be set to `ON` (case-insensitive). Resources missing this setting or with `value` not equal to `ON` are flagged as misconfigured.

Secure configuration example:

```yaml
- name: Ensure log_checkpoints is enabled
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: my-rg
    server_name: my-pg-server
    name: log_checkpoints
    value: "ON"
    state: present
```

## Compliant Code Examples
```yaml
- name: Update PostgreSQL Server setting
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_checkpoints
    value: on
- name: Update PostgreSQL Server setting2
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_checkpoints
    value: On
- name: Update PostgreSQL Server setting3
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_checkpoints
    value: ON
- name: Update PostgreSQL Server setting4
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_checkpoints
    value: on
- name: Update PostgreSQL Server setting5
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_checkpoints
    value: On
- name: Update PostgreSQL Server setting6
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_checkpoints
    value: ON

```
## Non-Compliant Code Examples
```yaml
---
- name: Update PostgreSQL Server setting
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_checkpoints
    value: off
- name: Update PostgreSQL Server setting2
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_checkpoints
    value: Off
- name: Update PostgreSQL Server setting3
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_checkpoints
    value: OFF
- name: Update PostgreSQL Server setting4
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_checkpoints
    value: "off"
- name: Update PostgreSQL Server setting5
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_checkpoints
    value: "Off"
- name: Update PostgreSQL Server setting6
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_checkpoints
    value: "OFF"

```