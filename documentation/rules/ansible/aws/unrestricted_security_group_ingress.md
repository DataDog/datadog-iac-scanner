---
title: "Unrestricted security group ingress"
group_id: "Ansible / AWS"
meta:
  name: "aws/unrestricted_security_group_ingress"
  id: "83c5fa4c-e098-48fc-84ee-0a537287ddd2"
  display_name: "Unrestricted security group ingress"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{</* copyable-code */>}}83c5fa4c-e098-48fc-84ee-0a537287ddd2{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_group_module.html)

### Description

Security group ingress rules must not allow traffic from the entire Internet (IPv4 `0.0.0.0/0` or IPv6 `::/0`) to specific ports. This exposes services to unauthorized access and automated attacks such as brute force and port scanning.

This rule inspects Ansible `amazon.aws.ec2_group` and `ec2_group` tasks and flags `rules` entries that define ports (via `from_port`/`to_port` or `ports`) where `cidr_ip` is `0.0.0.0/0` or `cidr_ipv6` is `::/0`. It also detects these values when CIDRs are provided as lists.

To remediate, restrict ingress to specific trusted CIDR ranges, use security group-to-security group references or VPN/bastion hosts, and remove or replace `0.0.0.0/0` and `::/0` from rules that open ports. 

Secure configuration example (restrict SSH to a trusted IPv4 range and allow HTTPS from a specific IPv6 range):

```yaml
- name: Create restricted SG
  amazon.aws.ec2_group:
    name: my-sg
    description: "Restrict SSH and HTTPS to trusted networks"
    rules:
      - proto: tcp
        from_port: 22
        to_port: 22
        cidr_ip: 10.0.0.0/24
      - proto: tcp
        from_port: 443
        to_port: 443
        cidr_ipv6: "2001:db8::/32"
```

## Compliant Code Examples
```yaml
- name: example1
  amazon.aws.ec2_group:
    name: example1
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    rules:
    - proto: tcp
      ports:
      - 80
      - 443
      - 8080-8099
      cidr_ip: 172.16.17.0/24
- name: example2
  amazon.aws.ec2_group:
    name: example2
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    rules:
    - proto: tcp
      ports:
      - 80
      - 443
      - 8080-8099
      cidr_ip:
      - 172.16.1.0/24
- name: example3
  amazon.aws.ec2_group:
    name: example3
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    rules:
    - proto: tcp
      ports:
      - 80
      - 443
      - 8080-8099
      cidr_ipv6: 2607:F8B0::/32
- name: example4
  amazon.aws.ec2_group:
    name: example4
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    rules:
    - proto: tcp
      ports:
      - 80
      - 443
      - 8080-8099
      cidr_ipv6:
      - 64:ff9b::/96
      - 2607:F8B0::/32

```
## Non-Compliant Code Examples
```yaml
---
- name: example1
  amazon.aws.ec2_group:
    name: example1
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    rules:
      - proto: tcp
        ports:
          - 80
          - 443
          - 8080-8099
        cidr_ip: 0.0.0.0/0
- name: example2
  amazon.aws.ec2_group:
    name: example2
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    rules:
      - proto: tcp
        ports:
          - 80
          - 443
          - 8080-8099
        cidr_ip:
          - 0.0.0.0/0
- name: example3
  amazon.aws.ec2_group:
    name: example3
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    rules:
      - proto: tcp
        ports:
          - 80
          - 443
          - 8080-8099
        cidr_ipv6: ::/0
- name: example4
  amazon.aws.ec2_group:
    name: example4
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    rules:
      - proto: tcp
        ports:
          - 80
          - 443
          - 8080-8099
        cidr_ipv6:
          - ::/0

```