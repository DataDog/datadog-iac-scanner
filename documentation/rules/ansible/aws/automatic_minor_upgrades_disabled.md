---
title: "Automatic minor upgrades disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/automatic_minor_upgrades_disabled"
  id: "ansible-aws-automatic-minor-upgrades-disabled"
  display_name: "Automatic minor upgrades disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `ansible-aws-automatic-minor-upgrades-disabled`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/rds_instance_module.html#parameter-auto_minor_version_upgrade)

### Description

RDS instances should have automatic minor engine upgrades enabled so critical security patches and bug fixes are applied promptly, preventing exposure to known vulnerabilities or compliance drift.

For Ansible RDS tasks using the `amazon.aws.rds_instance` or `rds_instance` modules, the `auto_minor_version_upgrade` property must be defined and set to `true`. Tasks that omit this property or set `auto_minor_version_upgrade: false` are flagged. Enabling this setting ensures minor engine patches are applied automatically during the instance's maintenance window.

Secure Ansible example:

```yaml
- name: create RDS instance with automatic minor upgrades
  amazon.aws.rds_instance:
    name: mydb
    engine: postgres
    instance_type: db.t3.medium
    auto_minor_version_upgrade: true
```

## Compliant Code Examples
```yaml
- name: negative - create minimal aurora instance in default VPC and default subnet group
  amazon.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: '{{ password }}'
    username: '{{ username }}'
    cluster_id: ansible-test-cluster
    auto_minor_version_upgrade: true
- name: negative - Create a DB instance using the default AWS KMS encryption key
  amazon.aws.rds_instance:
    db_instance_identifier: test-encrypted-db
    id: test-encrypted-db
    state: present
    engine: mariadb
    storage_encrypted: true
    db_instance_class: db.t2.medium
    username: '{{ username }}'
    password: '{{ password }}'
    allocated_storage: '{{ allocated_storage }}'
    auto_minor_version_upgrade: yes
- name: negative - Create a DB instance using the default AWS KMS encryption key
  amazon.aws.rds_instance:
    db_instance_identifier: test-encrypted-db
    id: test-encrypted-db
    state: present
    engine: mariadb
    storage_encrypted: true
    db_instance_class: db.t2.medium
    username: '{{ username }}'
    password: '{{ password }}'
    allocated_storage: '{{ allocated_storage }}'
    auto_minor_version_upgrade: true

```
## Non-Compliant Code Examples
```yaml
---
- name: community - create minimal aurora instance in default VPC and default subnet group
  amazon.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster
    auto_minor_version_upgrade: false
- name: community - Create a DB instance using the default AWS KMS encryption key
  amazon.aws.rds_instance:
    db_instance_identifier: test-encrypted-db
    id: test-encrypted-db
    state: present
    engine: mariadb
    storage_encrypted: True
    db_instance_class: db.t2.medium
    username: "{{ username }}"
    password: "{{ password }}"
    allocated_storage: "{{ allocated_storage }}"

```