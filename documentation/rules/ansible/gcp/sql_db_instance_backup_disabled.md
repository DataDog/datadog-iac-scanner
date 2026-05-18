---
title: "SQL DB instance backup disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/sql_db_instance_backup_disabled"
  id: "ansible-gcp-sql-db-instance-backup-disabled"
  display_name: "SQL DB instance backup disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-sql-db-instance-backup-disabled{{< /copyable-code >}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_sql_instance_module.html#parameter-settings/backup_configuration/enabled)

### Description

Cloud SQL instances must have backups enabled so you can recover from accidental deletion, data corruption, or ransomware. Without backups, data loss can be permanent and service restoration time increases.

For Ansible resources using `google.cloud.gcp_sql_instance` or `gcp_sql_instance`, ensure the `settings.backup_configuration.enabled` property is present and set to `true`. Resources missing `settings`, `settings.backup_configuration`, or `settings.backup_configuration.enabled`, or where `enabled` is `false`, are flagged. 

Secure configuration example:

```yaml
- name: Create Cloud SQL instance with backups enabled
  google.cloud.gcp_sql_instance:
    name: my-instance
    settings:
      tier: db-f1-micro
      backup_configuration:
        enabled: true
        start_time: "03:00"
```

## Compliant Code Examples
```yaml
- name: create a instance
  google.cloud.gcp_sql_instance:
    name: '{{ resource_name }}-2'
    settings:
      backup_configuration:
        binary_log_enabled: yes
        enabled: yes
      tier: db-n1-standard-1
    region: us-central1
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present

```
## Non-Compliant Code Examples
```yaml
---
- name: create a instance
  google.cloud.gcp_sql_instance:
    name: "{{ resource_name }}-2"
    region: us-central1
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a second instance
  google.cloud.gcp_sql_instance:
    name: "{{ resource_name }}-2"
    settings:
      tier: db-n1-standard-1
    region: us-central1
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a third instance
  google.cloud.gcp_sql_instance:
    name: "{{ resource_name }}-2"
    settings:
      backup_configuration:
        binary_log_enabled: yes
      tier: db-n1-standard-1
    region: us-central1
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a forth instance
  google.cloud.gcp_sql_instance:
    name: "{{ resource_name }}-2"
    settings:
      backup_configuration:
        binary_log_enabled: yes
        enabled: no
      tier: db-n1-standard-1
    region: us-central1
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```