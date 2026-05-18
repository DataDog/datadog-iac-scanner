---
title: "RDS instance with backup disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/rds_with_backup_disabled"
  id: "ansible-aws-rds-with-backup-disabled"
  display_name: "RDS instance with backup disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-rds-with-backup-disabled{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/rds_instance_module.html#parameter-backup_retention_period)

### Description

An RDS instance with automated backups disabled (`backup_retention_period` set to `0`) cannot perform point-in-time recovery and is at increased risk of permanent data loss and regulatory non‑compliance.

For Ansible resources using `amazon.aws.rds_instance` or `rds_instance`, the `backup_retention_period` property must be defined and set to an integer greater than `0` (value is in days). Resources missing this property or with `backup_retention_period: 0` are flagged. Set it to at least `1` (commonly 7 or more) based on your recovery objectives.

Secure configuration example for Ansible:

```yaml
- name: Create RDS instance with automated backups
  amazon.aws.rds_instance:
    db_instance_identifier: mydb
    engine: postgres
    instance_class: db.t3.medium
    allocated_storage: 20
    backup_retention_period: 7
```

## Compliant Code Examples
```yaml
- name: create minimal aurora instance in default VPC and default subnet group
  amazon.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: '{{ password }}'
    username: '{{ username }}'
    cluster_id: ansible-test-cluster  # This cluster must exist - see rds_cluster to manage it
    backup_retention_period: 5
- name: create minimal aurora instance in default VPC and default subnet group2
  amazon.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: '{{ password }}'
    username: '{{ username }}'
    cluster_id: ansible-test-cluster  # This cluster must exist - see rds_cluster to manage it

```
## Non-Compliant Code Examples
```yaml
---
- name: create minimal aurora instance in default VPC and default subnet group
  amazon.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster  # This cluster must exist - see rds_cluster to manage it
    backup_retention_period: 0

```