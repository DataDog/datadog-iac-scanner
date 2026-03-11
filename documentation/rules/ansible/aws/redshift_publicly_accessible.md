---
title: "Redshift Publicly Accessible"
group_id: "Ansible / AWS"
meta:
  name: "aws/redshift_publicly_accessible"
  id: "5c6b727b-1382-4629-8ba9-abd1365e5610"
  display_name: "Redshift Publicly Accessible"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `5c6b727b-1382-4629-8ba9-abd1365e5610`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/redshift_module.html)

### Description

Redshift clusters must not be publicly accessible because exposing cluster endpoints to the internet increases the risk of unauthorized access, data exfiltration, and brute-force attacks. For Ansible, check tasks using the `redshift` or `community.aws.redshift` modules: the `publicly_accessible` parameter must be set to `false`. This rule flags any task where `publicly_accessible` is `true`; explicitly set `publicly_accessible: false` in your task to ensure the cluster is not reachable from the public internet (relying on implicit defaults may be ambiguous across versions).

Secure configuration example:

```yaml
- name: Create Redshift cluster (not publicly accessible)
  community.aws.redshift:
    cluster_identifier: my-cluster
    node_type: dc2.large
    number_of_nodes: 2
    publicly_accessible: false
```

## Compliant Code Examples
```yaml
- name: Basic cluster provisioning example01
  community.aws.redshift:
    command: create
    node_type: ds1.xlarge
    identifier: new_cluster
    username: cluster_admin
    password: 1nsecur3
    publicly_accessible: no
- name: Basic cluster provisioning example02
  community.aws.redshift:
    command: create
    node_type: ds1.xlarge
    identifier: new_cluster
    username: cluster_admin
    password: 1nsecur3
- name: Basic cluster provisioning example03
  redshift:
    command: create
    node_type: ds1.xlarge
    identifier: new_cluster
    username: cluster_admin
    password: 1nsecur3
    publicly_accessible: false

```
## Non-Compliant Code Examples
```yaml
---
- name: Basic cluster provisioning example04
  community.aws.redshift:
    command: create
    node_type: ds1.xlarge
    identifier: new_cluster
    username: cluster_admin
    password: 1nsecur3
    publicly_accessible: yes
- name: Basic cluster provisioning example05
  community.aws.redshift:
    command: create
    node_type: ds1.xlarge
    identifier: new_cluster
    username: cluster_admin
    password: 1nsecur3
    publicly_accessible: True
- name: Basic cluster provisioning example06
  redshift:
    command: create
    node_type: ds1.xlarge
    identifier: new_cluster
    username: cluster_admin
    password: 1nsecur3
    publicly_accessible: Yes

```