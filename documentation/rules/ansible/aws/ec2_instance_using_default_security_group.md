---
title: "EC2 instance using default security group"
group_id: "Ansible / AWS"
meta:
  name: "aws/ec2_instance_using_default_security_group"
  id: "ansible-aws-ec2-instance-using-default-security-group"
  display_name: "EC2 instance using default security group"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-ec2-instance-using-default-security-group{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_instance_module.html#parameter-security_group)

### Description

Using the default security group for EC2 instances is unsafe. The default group is shared across the VPC, often broadly permissive for intra-VPC traffic, and cannot be scoped to least-privilege rules. This increases the risk of lateral movement and unintended exposure.

This rule inspects Ansible tasks that use the `amazon.aws.ec2_instance` or `ec2_instance` module and flags `security_group` or `security_groups` properties that reference the default security group. Both string and list forms are evaluated. Any value containing the word "default" (case-insensitive) is flagged and should be replaced with explicit, purpose-built security group names or IDs that restrict ingress and egress to only the required sources and ports.

Secure example using an explicit security group ID:

```yaml
- name: Launch EC2 with dedicated security group
  amazon.aws.ec2_instance:
    name: my-instance
    image_id: ami-0123456789abcdef0
    instance_type: t3.micro
    vpc_subnet_id: subnet-29e63245
    security_groups:
      - sg-0123456789abcdef0
    network:
      assign_public_ip: false
```

## Compliant Code Examples
```yaml
- name: Launch instance with custom SG
  amazon.aws.ec2_instance:
    name: web-server
    key_name: mykey
    instance_type: t2.micro
    image_id: ami-123456
    wait: yes
    security_group: my_sg
    vpc_subnet_id: subnet-29e63245
    network:
      assign_public_ip: false

```
## Non-Compliant Code Examples
```yaml
- name: Launch instance with default SG in list
  amazon.aws.ec2_instance:
    name: web-server-2
    key_name: mykey
    instance_type: t2.micro
    image_id: ami-123456
    wait: yes
    security_groups:
      - default
    vpc_subnet_id: subnet-29e63245
    network:
      assign_public_ip: false

```

```yaml
- name: Launch instance with default SG
  amazon.aws.ec2_instance:
    name: web-server
    key_name: mykey
    instance_type: t2.micro
    image_id: ami-123456
    wait: yes
    security_group: default
    vpc_subnet_id: subnet-29e63245
    network:
      assign_public_ip: false

```