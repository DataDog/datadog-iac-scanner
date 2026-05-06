---
title: "Redshift using default port"
group_id: "Ansible / AWS"
meta:
  name: "aws/redshift_using_default_port"
  id: "e01de151-a7bd-4db4-b49b-3c4775a5e881"
  display_name: "Redshift using default port"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{</* copyable-code */>}}e01de151-a7bd-4db4-b49b-3c4775a5e881{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/redshift_module.html#parameter-port)

### Description

Using the default Amazon Redshift port (5439) increases exposure because well-known ports are easy to discover and target with automated scanning and brute-force attempts.

In Ansible playbooks that use the `redshift` or `community.aws.redshift` modules, the `port` property must not be set to `5439`. Tasks with `port: 5439` are flagged. Choose a non-default port and restrict access using VPC private subnets and security group rules to limit which IPs or subnets can reach the cluster.

Secure example with a non-default port:

```yaml
- name: Create Redshift cluster with non-default port
  community.aws.redshift:
    cluster_identifier: my-redshift-cluster
    node_type: dc2.large
    master_username: masteruser
    master_user_password: secretpassword
    db_name: mydb
    port: 15432
```

## Compliant Code Examples
```yaml
- name: Redshift2
  community.aws.redshift:
    command: create
    node_type: ds1.xlarge
    identifier: new_cluster
    username: cluster_admin
    password: 1nsecur3
    port: 1150

```
## Non-Compliant Code Examples
```yaml
- name: Redshift
  community.aws.redshift:
    command: create
    node_type: ds1.xlarge
    identifier: new_cluster
    username: cluster_admin
    password: 1nsecur3
    port: 5439

```