---
title: "SQL Analysis Services port 2383 (TCP) is publicly accessible"
group_id: "Ansible / AWS"
meta:
  name: "aws/sql_analysis_services_port_2383_is_publicly_accessible"
  id: "ansible-aws-sql-analysis-services-port-2383-is-publicly-accessible"
  display_name: "SQL Analysis Services port 2383 (TCP) is publicly accessible"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ansible-aws-sql-analysis-services-port-2383-is-publicly-accessible`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_group_module.html)

### Description

Allowing TCP port 2383 (SQL Server Analysis Services) from the public internet (CIDR `0.0.0.0/0`) exposes the analysis service to unauthorized connections, increasing the risk of data exposure, unauthorized queries, and lateral movement into your environment.

For Ansible tasks using the `amazon.aws.ec2_group` or `ec2_group` module, this rule flags any `rules` entry where `cidr_ip` is `0.0.0.0/0`, `proto` is `tcp`, and the rule includes port 2383. Restrict access by specifying a limited CIDR range or referencing internal security groups instead of `0.0.0.0/0`, or remove the rule if public access is not required.

Secure configuration example:

```yaml
my_security_group:
  amazon.aws.ec2_group:
    name: my-sg
    rules:
      - proto: tcp
        from_port: 2383
        to_port: 2383
        cidr_ip: 10.0.0.0/24
```

## Compliant Code Examples
```yaml
- name: example using security group rule descriptions
  amazon.aws.ec2_group:
    name: awsEc2
    description: sg with rule descriptions
    vpc_id: vpc-xxxxxxxx
    profile: '{{ aws_profile }}'
    region: us-east-1
    rules:
    - proto: tcp
      ports:
      - 2383
      cidr_ip: aws_vpc.main.cidr_block
      rule_desc: allow all on port 2383

- name: example using security group rule descriptions 2
  amazon.aws.ec2_group:
    name: awsEc2
    description: sg with rule descriptions
    vpc_id: vpc-xxxxxxxx
    profile: '{{ aws_profile }}'
    region: us-east-1
    rules:
    - proto: udp
      ports:
      - 2383
      cidr_ip: 0.0.0.0/0
      rule_desc: allow all on port 2383

- name: example using security group rule descriptions 3
  amazon.aws.ec2_group:
    name: awsEc2
    description: sg with rule descriptions
    vpc_id: vpc-xxxxxxxx
    profile: '{{ aws_profile }}'
    region: us-east-1
    rules:
    - proto: tcp
      to_port: 4000
      from_port: 3000
      cidr_ip: 0.0.0.0/0
      rule_desc: allow all on port 2383

```
## Non-Compliant Code Examples
```yaml
---
- name: example using security group rule descriptions
  amazon.aws.ec2_group:
    name: awsEc2
    description: sg with rule descriptions
    vpc_id: vpc-xxxxxxxx
    profile: "{{ aws_profile }}"
    region: us-east-1
    rules:
      - proto: tcp
        ports:
          - 2383
        cidr_ip: 0.0.0.0/0
        rule_desc: allow all on port 2383

- name: example using security group rule descriptions 2
  amazon.aws.ec2_group:
    name: awsEc2
    description: sg with rule descriptions
    vpc_id: vpc-xxxxxxxx
    profile: "{{ aws_profile }}"
    region: us-east-1
    rules:
      - proto: tcp
        ports:
          - 2383
        cidr_ip: 0.0.0.0/0
        rule_desc: allow all on port 2383

- name: example using security group rule descriptions 3
  amazon.aws.ec2_group:
    name: awsEc2
    description: sg with rule descriptions
    vpc_id: vpc-xxxxxxxx
    profile: "{{ aws_profile }}"
    region: us-east-1
    rules:
      - proto: tcp
        to_port: -1
        from_port: -1
        cidr_ip: 0.0.0.0/0
        rule_desc: allow all on port 2383

- name: example using security group rule descriptions 4
  amazon.aws.ec2_group:
    name: awsEc2
    description: sg with rule descriptions
    vpc_id: vpc-xxxxxxxx
    profile: "{{ aws_profile }}"
    region: us-east-1
    rules:
      - proto: tcp
        ports:
          - 2000-3000
        cidr_ip: 0.0.0.0/0
        rule_desc: allow all on port 2383

- name: example using security group rule descriptions 5
  amazon.aws.ec2_group:
    name: awsEc2
    description: sg with rule descriptions
    vpc_id: vpc-xxxxxxxx
    profile: "{{ aws_profile }}"
    region: us-east-1
    rules:
      - proto: tcp
        to_port: 3000
        from_port: 2000
        cidr_ip: 0.0.0.0/0
        rule_desc: allow all on port 2383

```