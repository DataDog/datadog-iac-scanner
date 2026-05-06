---
title: "HTTP port open to internet"
group_id: "Ansible / AWS"
meta:
  name: "aws/http_port_open_to_internet"
  id: "a14ad534-acbe-4a8e-9404-2f7e1045646e"
  display_name: "HTTP port open to internet"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}a14ad534-acbe-4a8e-9404-2f7e1045646e{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_group_module.html#ansible-collections-amazon-aws-ec2-group-module)

### Description

Allowing HTTP (TCP port 80) from 0.0.0.0/0 in a Security Group exposes services to unauthenticated public access and subjects unencrypted traffic to eavesdropping and automated scanning. In Ansible tasks using `amazon.aws.ec2_group` or `ec2_group`, this rule flags `rules` entries where `cidr_ip` is `0.0.0.0/0` and the entry opens port 80.

Resources with such `rules` are flagged. To remediate, restrict `cidr_ip` to explicit trusted CIDR ranges or remove the public HTTP rule. Alternatively, serve traffic over HTTPS (port 443) terminated at a load balancer or proxy with appropriate access controls.

Secure example showing HTTP restricted to a trusted CIDR:

```yaml
- name: create security group with restricted HTTP
  amazon.aws.ec2_group:
    name: my-sg
    description: "example"
    rules:
      - proto: tcp
        from_port: 80
        to_port: 80
        cidr_ip: 10.0.0.0/16
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
      from_port: 67
      to_port: 82
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
      ports: 80
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
      ports: 79-90
      cidr_ip: 0.1.0.0/0

- name: example ec2 group4
  amazon.aws.ec2_group:
    name: example3
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
    - proto: tcp
      ports:
      - 100
      - 70-90
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
      - 80
      - 30-31
      cidr_ip: 0.0.0.0/10

- name: example ec2 group6
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
    - proto: tcp
      from_port: -1
      to_port: 82
      cidr_ip: 0.1.0.0/0

- name: example ec2 group7
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
    - proto: tcp
      from_port: 67
      to_port: -1
      cidr_ip: 1.0.0.0/0

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
        from_port: 67
        to_port: 82
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
        ports: 80
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
        ports: 79-90
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
          - 100
          - 70-90
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
          - 80
          - 30-31
        cidr_ip: 0.0.0.0/0

- name: example ec2 group6
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
      - proto: tcp
        from_port: -1
        to_port: 82
        cidr_ip: 0.0.0.0/0

- name: example ec2 group7
  amazon.aws.ec2_group:
    name: example
    description: an example EC2 group
    vpc_id: 12345
    region: eu-west-1
    aws_secret_key: SECRET
    aws_access_key: ACCESS
    rules:
      - proto: tcp
        from_port: 67
        to_port: -1
        cidr_ip: 0.0.0.0/0

```