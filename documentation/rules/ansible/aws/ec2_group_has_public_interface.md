---
title: "EC2 security group allows public access"
group_id: "Ansible / AWS"
meta:
  name: "aws/ec2_group_has_public_interface"
  id: "5330b503-3319-44ff-9b1c-00ee873f728a"
  display_name: "EC2 security group allows public access"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}5330b503-3319-44ff-9b1c-00ee873f728a{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_group_module.html)

### Description

Security group rules must not permit ingress from the public internet (`0.0.0.0/0` or `::/0`). Open rules expose instances to unauthorized access and automated attacks. In Ansible tasks using the `amazon.aws.ec2_group` or `ec2_group` modules, each entry in the `rules` list must not set `cidr_ip` to `0.0.0.0/0` or `cidr_ipv6` to `::/0`. This rule flags any `rules` item with those values. Instead, restrict access to specific CIDR ranges, reference other security groups, or require access via a bastion/VPN. 

Secure example with a restricted CIDR:

```yaml
- name: create ssh access for admin network
  amazon.aws.ec2_group:
    name: my-secgroup
    rules:
      - proto: tcp
        from_port: 22
        to_port: 22
        cidr_ip: 203.0.113.0/24
```

## Compliant Code Examples
```yaml
- name: example ec2 group2
  ec2_group1:
    name: example1
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1a
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
    - proto: tcp
      from_port: 80
      to_port: 80
      cidr_ip: 10.1.1.1/32

```
## Non-Compliant Code Examples
```yaml
- name: create minimal aurora instance in default VPC and default subnet group
  amazon.aws.rds_instance:
    engine: aurora
    db_instance_identifier: ansible-test-aurora-db-instance
    instance_type: db.t2.small
    password: "{{ password }}"
    username: "{{ username }}"
    cluster_id: ansible-test-cluster
    db_security_groups: ["example"]
- name: example ec2 group
  ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1a
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
      - proto: tcp
        from_port: 80
        to_port: 80
        cidr_ip: 0.0.0.0/0

```