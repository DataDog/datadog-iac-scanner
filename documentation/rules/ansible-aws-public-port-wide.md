---
title: "Public port with wide port range"
group_id: "Ansible / AWS"
meta:
  name: "aws/public_port_wide"
  id: "ansible-aws-public-port-wide"
  display_name: "Public port with wide port range"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-public-port-wide{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_group_module.html)

### Description

Security groups must not allow a wide port range to the entire internet. Exposing multiple ports publicly increases attack surface and enables broad port scanning, automated exploitation, and easier lateral movement.

For Ansible `amazon.aws.ec2_group` or `ec2_group` resources, check `rules[].from_port` and `rules[].to_port` and ensure rules where `to_port - from_port > 0` are not paired with `cidr_ip` set to `0.0.0.0/0` or `cidr_ipv6` set to `::/0`. Rules that require external access should restrict CIDR ranges to trusted networks or use specific single-port entries. Any rule defining a port range with an entire-network CIDR is flagged. 

Secure example restricting access to a single port and a specific CIDR:

```yaml
my_sg:
  name: my-security-group
  rules:
    - proto: tcp
      from_port: 22
      to_port: 22
      cidr_ip: 203.0.113.5/32
    - proto: tcp
      from_port: 443
      to_port: 443
      cidr_ip: 198.51.100.0/24
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
      cidr_ip: 0.0.0.0/0
    - proto: tcp
      from_port: 22
      to_port: 22
      cidr_ip: 10.0.0.0/8

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
        from_port: 80
        to_port: 82
        cidr_ip: 0.0.0.0/0
      - proto: tcp
        from_port: 2
        to_port: 22
        cidr_ipv6: ::/0

```