---
title: "DB security group with public scope"
group_id: "Ansible / AWS"
meta:
  name: "aws/db_security_group_with_public_scope"
  id: "ansible-aws-db-security-group-with-public-scope"
  display_name: "DB security group with public scope"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-db-security-group-with-public-scope{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Critical

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_group_module.html)

### Description

Security groups must not allow unrestricted IP ranges because a `cidr_ip` of `0.0.0.0/0` grants access from the entire Internet and exposes instances to unauthorized access, brute-force attacks, and data exfiltration.

For Ansible tasks using the `amazon.aws.ec2_group` or `ec2_group` modules, check the `rules` (ingress) and `rules_egress` (egress) entries and ensure each `cidr_ip` is not `0.0.0.0/0`. Prefer specific trusted CIDRs, private address ranges (for example `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), or references to other security groups.

This rule flags any `ec2_group.rules[].cidr_ip` or `ec2_group.rules_egress[].cidr_ip` set to a public scope such as `0.0.0.0/0`. Review and replace wide-open CIDRs with least-privilege network ranges or security-group references.

Secure Ansible example with restricted CIDRs:

```yaml
- name: Create internal security group
  amazon.aws.ec2_group:
    name: my-internal-sg
    description: Allow internal SSH only
    rules:
      - proto: tcp
        from_port: 22
        to_port: 22
        cidr_ip: 10.0.0.0/8
    rules_egress:
      - proto: -1
        from_port: 0
        to_port: 0
        cidr_ip: 10.0.0.0/8
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
  rules_egress:
  - proto: tcp
    from_port: 80
    to_port: 80
    cidr_ip: 10.1.1.1/32
    group_name: example-other
        # description to use if example-other needs to be created
    group_desc: other example EC2 group

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
        group_name: example
    rules_egress:
      - proto: tcp
        from_port: 80
        to_port: 80
        cidr_ip: 0.0.0.0/0
        group_name: example-other
        group_desc: other example EC2 group

```