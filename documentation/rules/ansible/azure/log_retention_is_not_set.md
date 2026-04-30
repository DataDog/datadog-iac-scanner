---
title: "Log retention is not set"
group_id: "Ansible / Azure"
meta:
  name: "azure/log_retention_is_not_set"
  id: "ansible-azure-log-retention-is-not-set"
  display_name: "Log retention is not set"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `ansible-azure-log-retention-is-not-set`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_postgresqlconfiguration_module.html)

### Description

PostgreSQL servers must retain logs to support security incident investigation and satisfy audit and compliance requirements. Without log retention, attackers or misconfigurations may go undetected and forensic analysis is impeded.

In Ansible playbooks using the `azure.azcollection.azure_rm_postgresqlconfiguration` or `azure_rm_postgresqlconfiguration` modules, the configuration entry with `name: log_retention` must have `value: on` (case-insensitive). Tasks missing the `log_retention` configuration or with `value` not equal to `on` are flagged as insecure.

Secure Ansible example:

```yaml
- name: Ensure PostgreSQL log_retention is enabled
  azure.azcollection.azure_rm_postgresqlconfiguration:
    resource_group: my-resource-group
    server_name: my-postgres-server
    name: log_retention
    value: on
```

## Compliant Code Examples
```yaml
- name: Update PostgreSQL Server setting
  azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_retention
    value: on

```
## Non-Compliant Code Examples
```yaml
---
- name: Update PostgreSQL Server setting
  azure_rm_postgresqlconfiguration:
    resource_group: myResourceGroup
    server_name: myServer
    name: log_retention
    value: off

```