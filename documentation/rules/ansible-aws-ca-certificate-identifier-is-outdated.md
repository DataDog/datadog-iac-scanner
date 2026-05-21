---
title: "CA certificate identifier is outdated"
group_id: "Ansible / AWS"
meta:
  name: "aws/ca_certificate_identifier_is_outdated"
  id: "ansible-aws-ca-certificate-identifier-is-outdated"
  display_name: "CA certificate identifier is outdated"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-ca-certificate-identifier-is-outdated{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/rds_instance_module.html#parameter-ca_certificate_identifier)

### Description

RDS instances must specify a CA certificate identifier so the database uses a known AWS CA for TLS connections and avoids broken or insecure certificate chains during CA rotations. For Ansible RDS resources (modules `amazon.aws.rds_instance` and `rds_instance`), the `ca_certificate_identifier` property must be defined and set to `rds-ca-2019`. Resources missing this property or specifying a different value are flagged. Update the value if AWS publishes a newer CA identifier.

Secure Ansible task example:

```yaml
- name: create RDS instance with CA
  amazon.aws.rds_instance:
    db_instance_identifier: my-db
    engine: mysql
    instance_class: db.t3.medium
    allocated_storage: 20
    username: admin
    password: secret
    ca_certificate_identifier: rds-ca-2019
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
    cluster_id: ansible-test-cluster
    ca_certificate_identifier: rds-ca-2019
- name: Create a DB instance using the default AWS KMS encryption key
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
    ca_certificate_identifier: rds-ca-2019

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
    cluster_id: ansible-test-cluster
    ca_certificate_identifier: rds-ca-2015
- name: create a DB instance using the default AWS KMS encryption key
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