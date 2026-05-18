---
title: "Security group ingress not restricted"
group_id: "Ansible / AWS"
meta:
  name: "aws/security_group_ingress_not_restricted"
  id: "ansible-aws-security-group-ingress-not-restricted"
  display_name: "Security group ingress not restricted"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-security-group-ingress-not-restricted{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_group_module.html)

### Description

Security groups must not allow unrestricted ingress from the public internet to all protocols and ports. Such rules expose instances to network scanning, exploitation, and unauthorized access.

In Ansible `amazon.aws.ec2_group` and `ec2_group` resources, each `rules` entry must not combine `from_port: 0` and `to_port: 0` with a non-explicit `proto` and an entire-network CIDR such as `cidr_ip: 0.0.0.0/0` or `cidr_ipv6: ::/0`.

The `proto` property must be an explicit protocol such as `tcp`, `udp`, `icmp`, `icmpv6`, or numeric values `1`, `6`, `17`, `58`. Rules where `proto` is missing or set to a catch-all (`-1`/`all`) with ports `0-0` and an entire-network CIDR are flagged.

To fix this, restrict the CIDR to trusted IP ranges or specify the exact protocol and port range required for the service.

Secure configuration example:

```yaml
- name: secure security group
  amazon.aws.ec2_group:
    name: my_sg
    description: "Allow SSH from admin network and HTTPS from anywhere"
    rules:
      - proto: tcp
        from_port: 22
        to_port: 22
        cidr_ip: 203.0.113.0/24
      - proto: tcp
        from_port: 443
        to_port: 443
        cidr_ip: 0.0.0.0/0
```

## Compliant Code Examples
```yaml
- name: example ec2 group v3
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    rules:
    - proto: tcp
      from_port: 80
      to_port: 80
      cidr_ip: 10.0.0.0/8
- name: example ec2 group v4
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    rules:
    - proto: tcp
      from_port: 80
      to_port: 80
      cidr_ipv6: 2001:DB8:8086:6502::/32

```
## Non-Compliant Code Examples
```yaml
- name: example ec2 group
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    rules:
      - proto: -1
        from_port: 0
        to_port: 0
        cidr_ip: 0.0.0.0/0
      - proto: all
        from_port: 0
        to_port: 0
        cidr_ip: 0.0.0.0/0
      - proto: 12121
        from_port: 0
        to_port: 0
        cidr_ip: 0.0.0.0/0
- name: example ec2 group v2
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    rules:
      - proto: -1
        from_port: 0
        to_port: 0
        cidr_ipv6: ::/0
      - proto: all
        from_port: 0
        to_port: 0
        cidr_ipv6: ::/0
      - proto: 121212
        from_port: 0
        to_port: 0
        cidr_ipv6: ::/0

```