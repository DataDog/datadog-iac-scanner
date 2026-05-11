---
title: "Unknown port exposed to internet"
group_id: "Ansible / AWS"
meta:
  name: "aws/unknown_port_exposed_to_internet"
  id: "ansible-aws-unknown-port-exposed-to-internet"
  display_name: "Unknown port exposed to internet"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ansible-aws-unknown-port-exposed-to-internet`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_group_module.html)

### Description

Security groups must not expose unknown or undocumented TCP ports to the entire Internet. Exposing unexpected ports increases attack surface and makes it easier for attackers to discover and exploit unintended services.

This rule inspects Ansible tasks using the `amazon.aws.ec2_group` and `ec2_group` modules. It checks each `rules` entry and flags rules where any port in the range from `from_port` to `to_port` is not found in the recognized TCP ports map and where `cidr_ip` equals `0.0.0.0/0` or `cidr_ipv6` equals `::/0` (entire network).

To remediate, restrict ingress to only known, required ports and limit CIDR ranges to trusted networks or reference other security groups. Review and document any non-standard ports before allowing public access. 

Secure example for Ansible `ec2_group` with a single, known port limited to a specific IPv4 range:

```yaml
- name: Create security group with restricted HTTPS access
  amazon.aws.ec2_group:
    name: example-sg
    rules:
      - proto: tcp
        from_port: 443
        to_port: 443
        cidr_ip: 203.0.113.0/24
```

## Compliant Code Examples
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
        from_port: 8001
        to_port: 8002
        cidr_ip: 0.0.0.0/0
      - proto: tcp
        from_port: 2222
        to_port: 2226
        cidr_ipv6: ::/0

```