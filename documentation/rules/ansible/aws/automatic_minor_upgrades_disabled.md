---
title: "Automatic Minor Upgrades Disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/automatic_minor_upgrades_disabled"
  id: "857f8808-e96a-4ba8-a9b7-f2d4ec6cad94"
  display_name: "Automatic Minor Upgrades Disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `857f8808-e96a-4ba8-a9b7-f2d4ec6cad94`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/rds_instance_module.html#parameter-auto_minor_version_upgrade)

### Description

RDS instances should have automatic minor engine upgrades enabled so critical security patches and bug fixes are applied promptly and database engines do not remain exposed to known vulnerabilities or drift out of compliance. For Ansible RDS tasks using the `community.aws.rds_instance` or `rds_instance` modules, the `auto_minor_version_upgrade` property must be defined and set to `true`. Tasks that omit this property or set `auto_minor_version_upgrade: false` will be flagged; enabling this setting ensures minor engine patches are applied automatically during the instance's maintenance window.

Secure Ansible example:

```yaml
- name: create RDS instance with automatic minor upgrades
  community.aws.rds_instance:
    name: mydb
    engine: postgres
    instance_type: db.t3.medium
    auto_minor_version_upgrade: true
```

## Compliant Code Examples
```yaml
- name: negative - create minimal aurora instance in default VPC and default subnet group
  community.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: '{{ password }}'
    username: '{{ username }}'
    cluster_id: ansible-test-cluster
    auto_minor_version_upgrade: true
- name: negative - Create a DB instance using the default AWS KMS encryption key
  community.aws.rds_instance:
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
  community.aws.rds_instance:
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
  community.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster
    auto_minor_version_upgrade: false
- name: community - Create a DB instance using the default AWS KMS encryption key
  community.aws.rds_instance:
    id: test-encrypted-db
    state: present
    engine: mariadb
    storage_encrypted: True
    db_instance_class: db.t2.medium
    username: "{{ username }}"
    password: "{{ password }}"
    allocated_storage: "{{ allocated_storage }}"

```