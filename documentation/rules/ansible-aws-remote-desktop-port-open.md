---
title: "Remote desktop port open to internet"
group_id: "Ansible / AWS"
meta:
  name: ""aws/remote_desktop_port_open""
  id: "ansible-aws-remote-desktop-port-open"
  display_name: "Remote desktop port open to internet"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-remote-desktop-port-open{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_group_module.html#ansible-collections-amazon-aws-ec2-group-module)

### Description

Security groups that allow Remote Desktop (RDP, TCP port 3389) from 0.0.0.0/0 expose Windows hosts to the public internet, increasing the likelihood of brute-force compromise, unauthorized access, and ransomware or lateral movement.

Ansible EC2 security group resources using the `amazon.aws.ec2_group` or `ec2_group` module must not include a rule where `cidr_ip` is `"0.0.0.0/0"` that permits port 3389 (that is, a rule with `proto: tcp`, `from_port: 3389`, `to_port: 3389`). Tasks with such a rule are flagged. Restrict RDP to specific trusted CIDR ranges, require bastion hosts or VPN access, or remove the rule entirely. 

Secure example restricting RDP to a trusted network:

```yaml
- name: Create security group with restricted RDP
  amazon.aws.ec2_group:
    name: my-sg
    description: SG with RDP restricted
    rules:
      - proto: tcp
        from_port: 3389
        to_port: 3389
        cidr_ip: 203.0.113.0/24
```

## Compliant Code Examples
```yaml
- name: example ec2 group1
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
    - proto: tcp
      from_port: 3380
      to_port: 3450
      cidr_ip: 0.0.0.0/1

- name: example ec2 group2
  amazon.aws.ec2_group:
    name: example2
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
    - proto: tcp
      ports: 3389
      cidr_ip: 0.0.1.0/0

- name: example ec2 group3
  amazon.aws.ec2_group:
    name: example3
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
    - proto: tcp
      ports: 3380-3450
      cidr_ip: 0.1.0.0/0

- name: example ec2 group4
  amazon.aws.ec2_group:
    name: example4
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
    - proto: tcp
      ports:
      - 80
      - 3380-3450
      cidr_ip: 10.0.0.0/0

- name: example ec2 group5
  amazon.aws.ec2_group:
    name: example5
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
    - proto: tcp
      ports:
      - 3389
      - 10-50
      cidr_ip: 10.0.0.0/0

- name: example ec2 group6
  amazon.aws.ec2_group:
    name: example1
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
    - proto: tcp
      from_port: -1
      to_port: 25
      cidr_ip: 0.1.0.0/0

- name: example ec2 group7
  amazon.aws.ec2_group:
    name: example1
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
    - proto: tcp
      from_port: 15
      to_port: -1
      cidr_ip: 0.0.0.1/0

```
## Non-Compliant Code Examples
```yaml
- name: example ec2 group1
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
      - proto: tcp
        from_port: 3380
        to_port: 3450
        cidr_ip: 0.0.0.0/0

- name: example ec2 group2
  amazon.aws.ec2_group:
    name: example2
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
      - proto: tcp
        ports: 3389
        cidr_ip: 0.0.0.0/0

- name: example ec2 group3
  amazon.aws.ec2_group:
    name: example3
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
      - proto: tcp
        ports: 3380-3450
        cidr_ip: 0.0.0.0/0

- name: example ec2 group4
  amazon.aws.ec2_group:
    name: example4
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
      - proto: tcp
        ports:
          - 80
          - 3380-3450
        cidr_ip: 0.0.0.0/0

- name: example ec2 group5
  amazon.aws.ec2_group:
    name: example5
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
      - proto: tcp
        ports:
          - 3389
          - 10-50
        cidr_ip: 0.0.0.0/0

- name: example ec2 group6
  amazon.aws.ec2_group:
    name: example1
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
      - proto: tcp
        from_port: -1
        to_port: 25
        cidr_ip: 0.0.0.0/0

- name: example ec2 group7
  amazon.aws.ec2_group:
    name: example1
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
      - proto: tcp
        from_port: 15
        to_port: -1
        cidr_ip: 0.0.0.0/0

```