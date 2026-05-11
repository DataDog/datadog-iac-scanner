---
title: "PostgreSQL log connections disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/postgresql_log_connections_disabled"
  id: "ansible-gcp-postgresql-log-connections-disabled"
  display_name: "PostgreSQL log connections disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-postgresql-log-connections-disabled{{< /copyable-code >}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_sql_instance_module.html#parameter-settings/database_flags)

### Description

PostgreSQL Cloud SQL instances must have the `log_connections` flag set to `on` so connection events are recorded for auditing and to help detect suspicious or unauthorized access. For Ansible resources using `google.cloud.gcp_sql_instance` or `gcp_sql_instance`, the `settings.databaseFlags` property must include an entry with `name: log_connections` and `value: on`. Resources missing `settings` or `settings.databaseFlags`, or where `log_connections` is absent or set to `off`, are flagged.

Secure Ansible example:

```yaml
- name: Create PostgreSQL Cloud SQL instance with connection logging enabled
  google.cloud.gcp_sql_instance:
    name: my-postgres-instance
    database_version: POSTGRES_13
    settings:
      tier: db-custom-1-3840
      databaseFlags:
        - name: log_connections
          value: "on"
```

## Compliant Code Examples
```yaml
- name: create a instance
  google.cloud.gcp_sql_instance:
    name: my-postgres-instance
    settings:
      databaseFlags:
      - name: log_connections
        value: on
      tier: db-n1-standard-1
    region: us-central1
    project: test_project
    database_version: POSTGRES_9_6
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: create instance
  google.cloud.gcp_sql_instance:
    name: my-postgres-instance
    settings:
      databaseFlags:
      - name: log_connections
        value: off
      tier: db-n1-standard-1
    region: us-central1
    project: test_project
    database_version: POSTGRES_9_6
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create another instance
  google.cloud.gcp_sql_instance:
    name: my-postgres-instance-2
    settings:
      tier: db-n1-standard-1
    region: us-central1
    project: test_project
    database_version: POSTGRES_9_6
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```