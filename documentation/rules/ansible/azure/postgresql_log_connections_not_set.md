---
title: "PostgreSQL log connections not set"
group_id: "Ansible / Azure"
meta:
  name: "azure/postgresql_log_connections_not_set"
  id: "ansible-azure-postgresql-log-connections-not-set"
  display_name: "PostgreSQL log connections not set"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-azure-postgresql-log-connections-not-set{{< /copyable-code >}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_postgresqlconfiguration_module.html)

### Description

PostgreSQL servers must have the server parameter `log_connections` set to `ON` so connection events are recorded for auditing and intrusion detection. Without this logging, connection attempts and session activity can go unnoticed, hampering incident investigation and compliance.

In Ansible, tasks using the `azure.azcollection.azure_rm_postgresqlconfiguration` or `azure_rm_postgresqlconfiguration` modules must set the `name` property to `log_connections` and the `value` property to `ON`. This rule flags tasks where `name` equals `log_connections` (case-insensitive) and `value` is missing or not `ON` (case-insensitive). Secure configuration example:

```yaml
- name: Enable PostgreSQL connection logging
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: my-rg
    server_name: my-pg-server
    name: log_connections
    value: "ON"
```

## Compliant Code Examples
```yaml
- name: Update PostgreSQL Server setting
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_connections
    value: on
- name: Update PostgreSQL Server setting2
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_connections
    value: On
- name: Update PostgreSQL Server setting3
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_connections
    value: ON
- name: Update PostgreSQL Server setting4
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_connections
    value: on
- name: Update PostgreSQL Server setting5
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_connections
    value: On
- name: Update PostgreSQL Server setting6
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_connections
    value: ON

```
## Non-Compliant Code Examples
```yaml
---
- name: Update PostgreSQL Server setting
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_connections
    value: off
- name: Update PostgreSQL Server setting2
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_connections
    value: Off
- name: Update PostgreSQL Server setting3
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_connections
    value: OFF
- name: Update PostgreSQL Server setting4
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_connections
    value: "off"
- name: Update PostgreSQL Server setting5
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_connections
    value: "Off"
- name: Update PostgreSQL Server setting6
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_connections
    value: "OFF"

```