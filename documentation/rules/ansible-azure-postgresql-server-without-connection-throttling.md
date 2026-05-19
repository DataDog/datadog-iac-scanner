---
title: "PostgreSQL server without connection throttling"
group_id: "Ansible / Azure"
meta:
  name: "azure/postgresql_server_without_connection_throttling"
  id: "ansible-azure-postgresql-server-without-connection-throttling"
  display_name: "PostgreSQL server without connection throttling"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-azure-postgresql-server-without-connection-throttling{{< /copyable-code >}}

**Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_postgresqlconfiguration_module.html)

### Description

Connection throttling must be enabled on PostgreSQL servers to limit concurrent connection attempts and prevent resource exhaustion or availability degradation from runaway clients or connection storms.

This rule checks Ansible tasks using the `azure.azcollection.azure_rm_postgresqlconfiguration` or `azure_rm_postgresqlconfiguration` module where `name` equals `connection_throttling`. The `value` property must be set to `ON` (case-insensitive). Resources missing this setting or with `value` set to `OFF` (or any value other than `ON`) are flagged as an incorrect configuration.

Secure Ansible task example:

```yaml
- name: Enable connection throttling on PostgreSQL server
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myPostgresServer
    name: connection_throttling
    value: ON
```

## Compliant Code Examples
```yaml
- name: Update PostgreSQL Server setting
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: connection_throttling
    value: on
- name: Update PostgreSQL Server setting2
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: connection_throttling
    value: On
- name: Update PostgreSQL Server setting3
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: connection_throttling
    value: ON
- name: Update PostgreSQL Server setting4
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: connection_throttling
    value: on
- name: Update PostgreSQL Server setting5
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: connection_throttling
    value: On
- name: Update PostgreSQL Server setting6
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: connection_throttling
    value: ON

```
## Non-Compliant Code Examples
```yaml
---
- name: Update PostgreSQL Server setting
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: connection_throttling
    value: off
- name: Update PostgreSQL Server setting2
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: connection_throttling
    value: Off
- name: Update PostgreSQL Server setting3
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: connection_throttling
    value: OFF
- name: Update PostgreSQL Server setting4
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: connection_throttling
    value: "off"
- name: Update PostgreSQL Server setting5
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: connection_throttling
    value: "Off"
- name: Update PostgreSQL Server setting6
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: connection_throttling
    value: "OFF"

```