---
title: "RDS instance uses a default port"
group_id: "Ansible / AWS"
meta:
  name: "aws/rds_using_default_port"
  id: "ansible-aws-rds-using-default-port"
  display_name: "RDS instance uses a default port"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ansible-aws-rds-using-default-port`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/rds_instance_module.html#parameter-port)

### Description

Using the database engine's default port makes instances easy for attackers to discover and target with automated scanning and exploit tooling, increasing the likelihood of brute-force, credential stuffing, or other network-based attacks. For Ansible RDS tasks using the `amazon.aws.rds_instance` or `rds_instance` modules, the `port` property must not be set to the engine default. Choose a non-default port and ensure access is restricted at the network level (security groups/ACLs).

This rule flags module tasks where `port` equals the engine default: MySQL/MariaDB/Aurora = 3306, PostgreSQL = 5432, Oracle = 1521, and SQL Server = 1433. This check flags explicit `port` settings that match defaults. If `port` is omitted, the engine may still use its default port, so also verify engine behavior and enforce least-privilege network access.

Secure configuration example (MySQL using a non-default port):

```yaml
- name: Create RDS instance with non-default port
  amazon.aws.rds_instance:
    db_instance_identifier: my-db
    engine: mysql
    port: 3307
```

## Compliant Code Examples
```yaml
- name: create minimal aurora instance in default VPC and default subnet group
  amazon.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster  # This cluster must exist - see rds_cluster to manage it
    backup_retention_period: 7
    port: 3307

```

```yaml
- name: create minimal aurora instance in default VPC and default subnet group2
  amazon.aws.rds_instance:
    engine: sqlserver-ee
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster  # This cluster must exist - see rds_cluster to manage it
    backup_retention_period: 7
    port: 1434

```

```yaml
- name: create minimal aurora instance in default VPC and default subnet group2
  amazon.aws.rds_instance:
    engine: postgres
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster  # This cluster must exist - see rds_cluster to manage it
    backup_retention_period: 7
    port: 5433

```
## Non-Compliant Code Examples
```yaml
- name: create minimal aurora instance in default VPC and default subnet group2
  amazon.aws.rds_instance:
    engine: postgres
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster  # This cluster must exist - see rds_cluster to manage it
    backup_retention_period: 7
    port: 5432

```

```yaml
- name: create minimal aurora instance in default VPC and default subnet group2
  amazon.aws.rds_instance:
    engine: oracle-ee
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster  # This cluster must exist - see rds_cluster to manage it
    backup_retention_period: 7
    port: 1521

```

```yaml
- name: create minimal aurora instance in default VPC and default subnet group2
  amazon.aws.rds_instance:
    engine: sqlserver-ee
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster  # This cluster must exist - see rds_cluster to manage it
    backup_retention_period: 7
    port: 1433

```