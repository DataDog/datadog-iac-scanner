---
title: "DB security group open to large scope"
group_id: "Ansible / AWS"
meta:
  name: "aws/db_security_group_open_to_large_scope"
  id: "ea0ed1c7-9aef-4464-b7c7-94c762da3640"
  display_name: "DB security group open to large scope"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}ea0ed1c7-9aef-4464-b7c7-94c762da3640{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_group_module.html#ansible-collections-amazon-aws-ec2-group-module)

### Description

Security group rules that use CIDR blocks containing 256 or more IP addresses broaden the attack surface and make unauthorized access or lateral movement easier.

For Ansible EC2 security groups (modules `amazon.aws.ec2_group` and `ec2_group`), ensure each rule's `cidr_ip` is a CIDR with a prefix length greater than 24 (for example `/25`–`/32`) so the subnet contains fewer than 256 addresses. This rule flags any task where `rules[].cidr_ip` has a prefix length of 24 or less (for example, `10.0.0.0/24`, `10.0.0.0/16`, or `0.0.0.0/0`). If broader access is required, prefer tighter subnetting, explicit host IPs, or security-group references instead of large CIDR ranges.

Secure Ansible example with a narrow CIDR (/32 single host):

```yaml
- name: create restrictive security group
  amazon.aws.ec2_group:
    name: my-sg
    rules:
      - proto: tcp
        from_port: 22
        to_port: 22
        cidr_ip: 10.0.0.5/32
```

## Compliant Code Examples
```yaml
- name: example ec2 group2
  ec2_group:
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
      - proto: tcp
        from_port: 22
        to_port: 22
        cidr_ip: 10.0.0.0/8
      - proto: tcp
        from_port: 443
        to_port: 443
        group_id: amazon-elb/sg-87654321/amazon-elb-sg
      - proto: tcp
        from_port: 3306
        to_port: 3306
        group_id: 123412341234/sg-87654321/exact-name-of-sg
      - proto: udp
        from_port: 10050
        to_port: 10050
        cidr_ip: 10.0.0.0/8
      - proto: udp
        from_port: 10051
        to_port: 10051
        group_id: sg-12345678
      - proto: icmp
        from_port: 8 # icmp type, -1 = any type
        to_port: -1 # icmp subtype, -1 = any subtype
        cidr_ip: 192.168.1.0/24
      - proto: all
        # the containing group name may be specified here
        group_name: example

```