---
title: "PostgreSQL Misconfigured Logging Duration Flag"
group_id: "Ansible / GCP"
meta:
  name: "gcp/postgresql_misconfigured_logging_duration_flag"
  id: "aed98a2a-e680-497a-8886-277cea0f4514"
  display_name: "PostgreSQL Misconfigured Logging Duration Flag"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `aed98a2a-e680-497a-8886-277cea0f4514`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_sql_instance_module.html#parameter-settings/database_flags)

### Description

The PostgreSQL `log_min_duration_statement` flag controls whether SQL statements are recorded for slow queries; if it is not set to `-1`, statement text for slow queries may be written to logs, increasing the risk of exposing sensitive data and creating additional compliance and log-management burden. For Ansible-managed Cloud SQL PostgreSQL instances, ensure the `settings.database_flags` entry for `log_min_duration_statement` is present and set to `-1` in `google.cloud.gcp_sql_instance` or `gcp_sql_instance` tasks. Resources missing this flag or with a different value will be flagged; use `-1` (integer) to disable duration-based statement logging.

Secure configuration example:

```yaml
- name: Create Cloud SQL PostgreSQL instance
  google.cloud.gcp_sql_instance:
    name: my-pg-instance
    database_version: POSTGRES_13
    region: us-central1
    settings:
      database_flags:
        - name: log_min_duration_statement
          value: -1
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
      - name: log_min_duration_statement
        value: -1
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
      - name: log_min_duration_statement
        value: 0
      tier: db-n1-standard-1
    state: present

```