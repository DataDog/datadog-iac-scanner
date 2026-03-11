---
title: "EC2 Instance Using Default Security Group"
group_id: "Ansible / AWS"
meta:
  name: "aws/ec2_instance_using_default_security_group"
  id: "8d03993b-8384-419b-a681-d1f55149397c"
  display_name: "EC2 Instance Using Default Security Group"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `8d03993b-8384-419b-a681-d1f55149397c`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_module.html#parameter-group)

### Description

Using the default security group for EC2 instances is unsafe because the default group is shared, often broadly permissive for intra-VPC traffic, and cannot be scoped to least-privilege rules, which increases the risk of lateral movement and unintended exposure. This rule inspects Ansible tasks that use the `amazon.aws.ec2` or legacy `ec2` module and flags `group` or `group_id` properties that reference the default security group. Both string and list forms are evaluated; any value containing the word "default" (case-insensitive) will be flagged and should be replaced with explicit, purpose-built security group names or IDs that restrict ingress and egress to only the required sources and ports. Secure example using an explicit security group ID:

```yaml
- name: Launch EC2 with dedicated security group
  amazon.aws.ec2:
    name: my-instance
    image: ami-0123456789abcdef0
    instance_type: t3.micro
    group_id:
      - sg-0123456789abcdef0
```

## Compliant Code Examples
```yaml
- name: example2
  amazon.aws.ec2:
    key_name: mykey
    instance_type: t2.micro
    image: ami-123456
    wait: yes
    group: my_sg
    count: 3
    vpc_subnet_id: subnet-29e63245
    assign_public_ip: yes

```
## Non-Compliant Code Examples
```yaml
- name: example2
  amazon.aws.ec2:
    key_name: mykey
    instance_type: t2.micro
    image: ami-123456
    wait: yes
    group:
      - default
    count: 3
    vpc_subnet_id: subnet-29e63245
    assign_public_ip: yes

```

```yaml
- name: example
  amazon.aws.ec2:
    key_name: mykey
    instance_type: t2.micro
    image: ami-123456
    wait: yes
    group: default
    count: 3
    vpc_subnet_id: subnet-29e63245
    assign_public_ip: yes

```