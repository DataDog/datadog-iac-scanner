---
title: "PostgreSQL misconfigured log messages flag"
group_id: "Ansible / GCP"
meta:
  name: "gcp/postgresql_misconfigured_log_messages_flag"
  id: "ansible-gcp-postgresql-misconfigured-log-messages-flag"
  display_name: "PostgreSQL misconfigured log messages flag"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-postgresql-misconfigured-log-messages-flag{{< /copyable-code >}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_sql_instance_module.html#parameter-settings/database_flags)

### Description

PostgreSQL instances must have the `log_min_messages` flag set to a valid verbosity level. This ensures critical database events are recorded for detection and forensic analysis, while avoiding overly verbose debug logs that can expose sensitive information.

For Ansible Google Cloud SQL resources using the `google.cloud.gcp_sql_instance` (or `gcp_sql_instance`) module, ensure `settings.database_flags` contains an entry with `name: "log_min_messages"` and `value` set to one of the following: `fatal`, `panic`, `log`, `error`, `warning`, `notice`, `info`, `debug1`, `debug2`, `debug3`, `debug4`, or `debug5`. Resources missing this entry or using a value outside the allowed set are flagged.

Secure configuration example:

```yaml
- name: Create Cloud SQL instance with secure logging
  google.cloud.gcp_sql_instance:
    name: my-sql-instance
    settings:
      database_flags:
        - name: log_min_messages
          value: warning
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
      - name: log_min_messages
        value: log
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
      - name: log_min_messages
        value: debug6
      tier: db-n1-standard-1
    state: present

```