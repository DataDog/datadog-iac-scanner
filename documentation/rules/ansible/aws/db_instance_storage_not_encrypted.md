---
title: "DB instance storage not encrypted"
group_id: "Ansible / AWS"
meta:
  name: "aws/db_instance_storage_not_encrypted"
  id: "7dfb316c-a6c2-454d-b8a2-97f147b0c0ff"
  display_name: "DB instance storage not encrypted"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `7dfb316c-a6c2-454d-b8a2-97f147b0c0ff`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/rds_instance_module.html)

### Description

RDS instances must have storage encryption enabled to protect data at rest, including database files, automated backups, and snapshots. Without encryption, this data is exposed to unauthorized access if storage media or snapshots are compromised.

For Ansible resources using the `amazon.aws.rds_instance` or `rds_instance` modules, set `storage_encrypted` to `true`. If you are using a customer-managed key, also define `kms_key_id`. This rule flags instances where `storage_encrypted` is undefined or set to `false` and no `kms_key_id` is provided.

```yaml
- name: Create encrypted RDS instance
  amazon.aws.rds_instance:
    db_instance_identifier: mydb
    engine: mysql
    allocated_storage: 20
    master_username: admin
    master_user_password: secret
    storage_encrypted: true
    kms_key_id: arn:aws:kms:us-east-1:123456789012:key/abcd-ef01-2345-6789-abcd
```

## Compliant Code Examples
```yaml
- name: foo
  amazon.aws.rds_instance:
    db_instance_identifier: my-db-1
    id: test-encrypted-db
    state: present
    engine: mariadb
    storage_encrypted: true
    db_instance_class: db.t2.medium
    username: '{{ username }}'
    password: '{{ password }}'
    allocated_storage: '{{ allocated_storage }}'
- name: foo2
  amazon.aws.rds_instance:
    db_instance_identifier: my-db-2
    id: test-encrypted-db
    state: present
    engine: mariadb
    storage_encrypted: yes
    db_instance_class: db.t2.medium
    username: '{{ username }}'
    password: '{{ password }}'
    allocated_storage: '{{ allocated_storage }}'
- name: foo3
  amazon.aws.rds_instance:
    db_instance_identifier: my-db-3
    id: test-encrypted-db
    state: present
    engine: mariadb
    kms_key_id: sup3rstr0ngK3y
    db_instance_class: db.t2.medium
    username: '{{ username }}'
    password: '{{ password }}'
    allocated_storage: '{{ allocated_storage }}'

```
## Non-Compliant Code Examples
```yaml
---
- name: foo
  amazon.aws.rds_instance:
    db_instance_identifier: my-db-1
    id: test-encrypted-db
    state: present
    engine: mariadb
    storage_encrypted: False
    db_instance_class: db.t2.medium
    username: "{{ username }}"
    password: "{{ password }}"
    allocated_storage: "{{ allocated_storage }}"
- name: foo2
  amazon.aws.rds_instance:
    db_instance_identifier: my-db-2
    id: test-encrypted-db
    state: present
    engine: mariadb
    storage_encrypted: no
    db_instance_class: db.t2.medium
    username: "{{ username }}"
    password: "{{ password }}"
    allocated_storage: "{{ allocated_storage }}"
- name: foo3
  amazon.aws.rds_instance:
    db_instance_identifier: my-db-3
    id: test-encrypted-db
    state: present
    engine: mariadb
    db_instance_class: db.t2.medium
    username: "{{ username }}"
    password: "{{ password }}"
    allocated_storage: "{{ allocated_storage }}"

```