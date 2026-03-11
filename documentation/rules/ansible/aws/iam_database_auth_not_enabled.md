---
title: "IAM Database Auth Not Enabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/iam_database_auth_not_enabled"
  id: "0ed012a4-9199-43d2-b9e4-9bd049a48aa4"
  display_name: "IAM Database Auth Not Enabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `0ed012a4-9199-43d2-b9e4-9bd049a48aa4`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/rds_instance_module.html)

### Description

IAM database authentication should be enabled to avoid reliance on static database passwords and to centralize access control, reducing the risk of credential leakage and making rotation and auditing easier. For Ansible RDS resources using the `community.aws.rds_instance` or `rds_instance` modules, the `enable_iam_database_authentication` property must be defined and set to `true`. This check only applies to engines, engine versions, and instance types that support IAM authentication (the policy validates `engine`, `engine_version`, and `instance_type`); resources where the property is missing or set to `false` will be flagged. Secure Ansible example:

```yaml
- name: Create RDS instance with IAM auth enabled
  community.aws.rds_instance:
    db_instance_identifier: mydb
    engine: mysql
    engine_version: "8.0"
    instance_type: db.t3.medium
    enable_iam_database_authentication: true
```

## Compliant Code Examples
```yaml
- name: create minimal aurora instance in default VPC and default subnet group
  community.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: '{{ password }}'
    username: '{{ username }}'
    cluster_id: ansible-test-cluster
    enable_iam_database_authentication: true


- name: Create a DB instance using the default AWS KMS encryption key
  community.aws.rds_instance:
    id: test-encrypted-db
    state: present
    engine: mariadb
    storage_encrypted: true
    db_instance_class: db.t2.medium
    username: '{{ username }}'
    password: '{{ password }}'
    allocated_storage: '{{ allocated_storage }}'
    enable_iam_database_authentication: true

- name: remove the DB instance without a final snapshot
  community.aws.rds_instance:
    id: '{{ instance_id }}'
    state: absent
    skip_final_snapshot: true
    enable_iam_database_authentication: true

- name: remove the DB instance with a final snapshot
  community.aws.rds_instance:
    id: '{{ instance_id }}'
    state: absent
    final_snapshot_identifier: '{{ snapshot_id }}'
    enable_iam_database_authentication: true

- name: create minimal aurora instance in default VPC and default subnet group
  community.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster
    enable_iam_database_authentication: "No"

- name: create minimal aurora instance in default VPC and default subnet group
  community.aws.rds_instance:
    engine: mariadb
    engine_version: 10.2.43
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster

```
## Non-Compliant Code Examples
```yaml
- name: create minimal aurora instance in default VPC and default subnet group
  community.aws.rds_instance:
    engine: mysql
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster
    enable_iam_database_authentication: "No"


- name: Create a DB instance using the default AWS KMS encryption key
  community.aws.rds_instance:
    id: test-encrypted-db
    state: present
    engine: mariadb
    storage_encrypted: True
    db_instance_class: db.t2.medium
    username: "{{ username }}"
    password: "{{ password }}"
    allocated_storage: "{{ allocated_storage }}"
    enable_iam_database_authentication: false

```