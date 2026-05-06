---
title: "Redshift cluster is not encrypted"
group_id: "Ansible / AWS"
meta:
  name: "aws/redshift_not_encrypted"
  id: "6a647814-def5-4b85-88f5-897c19f509cd"
  display_name: "Redshift cluster is not encrypted"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** {{</* copyable-code */>}}6a647814-def5-4b85-88f5-897c19f509cd{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#encrypted)

### Description

AWS Redshift clusters must have storage encryption enabled to protect sensitive data at rest, including data on cluster disks, automated snapshots, and backups. Without encryption, data can be exposed if storage media or snapshots are compromised. For Ansible, tasks using the `redshift` or `community.aws.redshift` modules that create or modify clusters must set the `encrypted` parameter to `true`. Resources where `encrypted` is omitted or explicitly set to `false` are flagged because the modules default to unencrypted when the property is not provided. Optionally specify a customer-managed KMS key with `kms_key_id` when `encrypted: true` is required.

Secure example:

```yaml
- name: Create encrypted Redshift cluster
  community.aws.redshift:
    command: create
    cluster_identifier: my-cluster
    node_type: dc2.large
    number_of_nodes: 2
    encrypted: true
    kms_key_id: arn:aws:kms:us-east-1:123456789012:key/abcd-ef01-2345-6789
```

## Compliant Code Examples
```yaml
- name: Basic cluster provisioning example
  community.aws.redshift:
    identifier: tf-redshift-cluster
    command: create
    db_name: mydb
    username: foo
    password: Mustbe8characters
    node_type: dc1.large
    cluster_type: single-node
    encrypted: true
- name: Basic cluster provisioning example2
  community.aws.redshift:
    identifier: tf-redshift-cluster
    command: create
    db_name: mydb
    username: foo
    password: Mustbe8characters
    node_type: dc1.large
    cluster_type: single-node
    encrypted: yes

```
## Non-Compliant Code Examples
```yaml
- name: Basic cluster provisioning example
  community.aws.redshift:
    identifier: tf-redshift-cluster
    command: create
    db_name: mydb
    username: foo
    password: Mustbe8characters
    node_type: dc1.large
    cluster_type: single-node
- name: Basic cluster provisioning example2
  community.aws.redshift:
    identifier: tf-redshift-cluster
    command: create
    db_name: mydb
    username: foo
    password: Mustbe8characters
    node_type: dc1.large
    cluster_type: single-node
    encrypted: false
- name: Basic cluster provisioning example3
  community.aws.redshift:
    identifier: tf-redshift-cluster
    command: create
    db_name: mydb
    username: foo
    password: Mustbe8characters
    node_type: dc1.large
    cluster_type: single-node
    encrypted: no

```