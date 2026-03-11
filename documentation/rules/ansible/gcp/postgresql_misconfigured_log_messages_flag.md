---
title: "PostgreSQL Misconfigured Log Messages Flag"
group_id: "Ansible / GCP"
meta:
  name: "gcp/postgresql_misconfigured_log_messages_flag"
  id: "28a757fc-3d8f-424a-90c0-4233363b2711"
  display_name: "PostgreSQL Misconfigured Log Messages Flag"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `28a757fc-3d8f-424a-90c0-4233363b2711`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_sql_instance_module.html#parameter-settings/database_flags)

### Description

PostgreSQL instances must have the `log_min_messages` flag set to a valid verbosity level so that critical database events are recorded for detection and forensic analysis, while avoiding overly verbose debug logs that can expose sensitive information. For Ansible Google Cloud SQL resources using the `google.cloud.gcp_sql_instance` (or `gcp_sql_instance`) module, ensure `settings.database_flags` contains an entry with `name: "log_min_messages"` and `value` set to one of: `fatal`, `panic`, `log`, `error`, `warning`, `notice`, `info`, `debug1`, `debug2`, `debug3`, `debug4`, or `debug5`. The `settings.database_flags` list must include this mapping and resources missing the entry or using a value outside the allowed set will be flagged.

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