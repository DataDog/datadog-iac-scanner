---
title: "PostgreSQL Logging Of Temporary Files Disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/postgresql_logging_of_temporary_files_disabled"
  id: "d6fae5b6-ada9-46c0-8b36-3108a2a2f77b"
  display_name: "PostgreSQL Logging Of Temporary Files Disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `d6fae5b6-ada9-46c0-8b36-3108a2a2f77b`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_sql_instance_module.html#parameter-settings/database_flags)

### Description

The PostgreSQL `log_temp_files` flag should be set to `0` so that all temporary file creation is logged, providing visibility into queries that spill to disk and helping detect potential data exposure or performance issues. Check Ansible Cloud SQL instance resources using the `google.cloud.gcp_sql_instance` or `gcp_sql_instance` modules; the `settings.database_flags` entry with `name: log_temp_files` must have `value: "0"`. Resources missing this flag or with a different value will be flagged. In Ansible, `database_flags` is a list of name/value pairs, so specify the flag explicitly as shown below.

```yaml
- name: Create Cloud SQL instance
  google.cloud.gcp_sql_instance:
    name: my-postgres
    database_version: POSTGRES_13
    settings:
      database_flags:
        - name: log_temp_files
          value: "0"
```

## Compliant Code Examples
```yaml
- name: sql_instance
  google.cloud.gcp_sql_instance:
    auth_kind: serviceaccount
    database_version: SQLSERVER_13_1
    name: '{{ resource_name }}-2'
    project: test_project
    region: us-central1
    service_account_file: /tmp/auth.pem
    settings:
      database_flags:
      - name: log_temp_files
        value: 0
      tier: db-n1-standard-1
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: sql_instance
  google.cloud.gcp_sql_instance:
    auth_kind: serviceaccount
    database_version: SQLSERVER_13_1
    name: "{{ resource_name }}-2"
    project: test_project
    region: us-central1
    service_account_file: /tmp/auth.pem
    settings:
      database_flags:
      - name: log_temp_files
        value: 1
      tier: db-n1-standard-1
    state: present

```