---
title: "PostgreSQL Log Duration Not Set"
group_id: "Ansible / Azure"
meta:
  name: "azure/postgresql_log_duration_not_set"
  id: "729ebb15-8060-40f7-9017-cb72676a5487"
  display_name: "PostgreSQL Log Duration Not Set"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `729ebb15-8060-40f7-9017-cb72676a5487`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_postgresqlconfiguration_module.html)

### Description

Enable the PostgreSQL server parameter `log_duration` to record statement execution durations; without duration logging, slow queries and malicious long-running activity can go undetected, hindering timely detection and forensic investigation. In Ansible tasks using the `azure.azcollection.azure_rm_postgresqlconfiguration` or `azure_rm_postgresqlconfiguration` module, the parameter entry with `name: log_duration` must have `value: 'ON'`. Tasks missing the `value` property or with a value other than `ON` (case-insensitive) will be flagged.

Secure Ansible task example:

```yaml
- name: Enable log_duration for PostgreSQL server
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myPostgresServer
    name: log_duration
    value: "ON"
```

## Compliant Code Examples
```yaml
- name: example1
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_duration
    value: on
- name: example2
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_duration
    value: On
- name: example3
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_duration
    value: ON
- name: example4
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_duration
    value: on
- name: example5
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_duration
    value: On
- name: example6
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_duration
    value: ON

```
## Non-Compliant Code Examples
```yaml
- name: example1
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_duration
    value: off
- name: example2
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_duration
    value: Off
- name: example3
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_duration
    value: OFF
- name: example4
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_duration
    value: "off"
- name: example5
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_duration
    value: "Off"
- name: example6
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_duration
    value: "OFF"

```