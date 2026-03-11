---
title: "PostgreSQL log_checkpoints Flag Not Set To ON"
group_id: "Ansible / GCP"
meta:
  name: "gcp/postgresql_log_checkpoints_flag_not_set_to_on"
  id: "89afe3f0-4681-4ce3-89ed-896cebd4277c"
  display_name: "PostgreSQL log_checkpoints Flag Not Set To ON"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `89afe3f0-4681-4ce3-89ed-896cebd4277c`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_sql_instance_module.html#parameter-settings/database_flags)

### Description

PostgreSQL Cloud SQL instances must have the `log_checkpoints` flag enabled so checkpoint events are recorded; without these logs, crash recovery and forensic analysis are hindered and it becomes harder to detect or investigate anomalous or destructive activity. For Ansible tasks using `google.cloud.gcp_sql_instance` or `gcp_sql_instance`, the `settings.databaseFlags` list must include an entry with `name: log_checkpoints` and `value: on`. Tasks that omit the `settings` block, omit `databaseFlags`, or have `log_checkpoints` set to any value other than `on` will be flagged. Secure example configuration in an Ansible task:

```yaml
- name: Create Cloud SQL PostgreSQL instance with checkpoint logging
  google.cloud.gcp_sql_instance:
    name: my-postgres-instance
    database_version: POSTGRES_13
    settings:
      databaseFlags:
        - name: log_checkpoints
          value: on
```

## Compliant Code Examples
```yaml
- name: create a instance
  google.cloud.gcp_sql_instance:
    name: GCP instance
    settings:
      databaseFlags:
      - name: log_checkpoints
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
    name: GCP instance
    settings:
      databaseFlags:
      - name: log_checkpoints
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
    name: GCP instance 2
    settings:
      tier: db-n1-standard-1
    region: us-central1
    project: test_project
    database_version: POSTGRES_9_6
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```