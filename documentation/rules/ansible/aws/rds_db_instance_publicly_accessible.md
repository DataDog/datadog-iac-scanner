---
title: "RDS DB instance is not publicly accessible"
group_id: "Ansible / AWS"
meta:
  name: "aws/rds_db_instance_publicly_accessible"
  id: "ansible-aws-rds-db-instance-publicly-accessible"
  display_name: "RDS DB instance is not publicly accessible"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `ansible-aws-rds-db-instance-publicly-accessible`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Critical

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/rds_instance_module.html#parameter-auto_minor_version_upgrade)

### Description

RDS instances must not be configured as publicly accessible. Exposing a database to the public internet increases the risk of unauthorized access and enables brute-force or credential-stuffing attacks.

In Ansible RDS tasks using the `amazon.aws.rds_instance` or `rds_instance` modules, ensure the `publicly_accessible` property is set to `false`. Tasks with `publicly_accessible: true` are flagged. If the property is omitted, the modules default to `false`, but explicitly setting it to `false` and placing instances in private subnets with restrictive security groups provides defense-in-depth.

Secure example:

```yaml
- name: Create RDS instance (private)
  amazon.aws.rds_instance:
    db_instance_identifier: mydb
    engine: postgres
    instance_class: db.t3.medium
    publicly_accessible: false
```

## Compliant Code Examples
```yaml
- name: create RDS instance in default VPC and default subnet group02
  amazon.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: '{{ password }}'
    username: '{{ username }}'
    cluster_id: ansible-test-cluster
    publicly_accessible: false
- name: create RDS instance in default VPC and default subnet group03
  rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: '{{ password }}'
    username: '{{ username }}'
    cluster_id: ansible-test-cluster

```
## Non-Compliant Code Examples
```yaml
---
- name: community - Create a DB instance using the default AWS KMS encryption key
  amazon.aws.rds_instance:
    db_instance_identifier: my-db-1
    id: test-encrypted-db
    state: present
    engine: mariadb
    storage_encrypted: True
    db_instance_class: db.t2.medium
    username: "{{ username }}"
    password: "{{ password }}"
    allocated_storage: "{{ allocated_storage }}"
    publicly_accessible: Yes
- name: Community - Basic MySQL provisioning example
  amazon.aws.rds_instance:
    db_instance_identifier: my-db-2
    command: create
    instance_name: new-database
    db_engine: MySQL
    size: 10
    instance_type: db.m1.small
    username: mysql_admin
    password: 1nsecure
    publicly_accessible: "true"
    tags:
      Environment: testing
      Application: cms

```