---
title: "Security group with unrestricted access to SSH"
group_id: "Ansible / AWS"
meta:
  name: "aws/security_group_with_unrestricted_access_to_ssh"
  id: "ansible-aws-security-group-with-unrestricted-access-to-ssh"
  display_name: "Security group with unrestricted access to SSH"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-security-group-with-unrestricted-access-to-ssh{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_group_module.html)

### Description

SSH (TCP port 22) must not be exposed to public CIDR ranges because it enables unauthorized remote access and increases the risk of brute-force or credential-stuffing attacks and lateral movement.

This check inspects Ansible tasks using `amazon.aws.ec2_group` or `ec2_group` and flags entries in the `rules` list where `from_port`/`to_port` cover port 22 (or are both `-1` indicating all ports) and `cidr_ip` or `cidr_ipv6` specify public CIDRs such as `0.0.0.0/0` or `::/0`. Limit `cidr_ip`/`cidr_ipv6` to specific trusted IP ranges, or remove SSH from the security group and enforce access through a bastion host or VPN. Any rule that leaves SSH open to public CIDRs is flagged. 

Secure example restricting SSH to a single trusted address:

```yaml
- name: my-secure-sg
  amazon.aws.ec2_group:
    name: my-secure-sg
    rules:
      - proto: tcp
        from_port: 22
        to_port: 22
        cidr_ip: 203.0.113.4/32
```

## Compliant Code Examples
```yaml
- name: example ec2 group v2
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    rules:
    - proto: tcp
      from_port: 80
      to_port: 80
      cidr_ip: 79.32.0.0/8
    - proto: tcp
      from_port: 80
      to_port: 80
      cidr_ipv6: 64:ff9b::/96

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
      - proto: tcp
        from_port: 22
        to_port: 22
        cidr_ip: 79.32.0.0/12
      - proto: tcp
        from_port: -1
        to_port: -1
        cidr_ip: 79.32.0.0/12
      - proto: tcp
        from_port: 22
        to_port: 22
        cidr_ipv6: 2607:F8B0::/24

```