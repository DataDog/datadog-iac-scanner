---
title: "Instance with no VPC"
group_id: "Ansible / AWS"
meta:
  name: "aws/instance_with_no_vpc"
  id: "61d1a2d0-4db8-405a-913d-5d2ce49dff6f"
  display_name: "Instance with no VPC"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `61d1a2d0-4db8-405a-913d-5d2ce49dff6f`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_instance_module.html)

### Description

EC2 instances must be launched into a VPC subnet so they are subject to VPC network controls such as security groups, network ACLs, private addressing, and VPC flow logs. Without a subnet assignment, instances can lack network isolation and be exposed to the public network or miss critical network monitoring.

For Ansible EC2 modules (`amazon.aws.ec2_instance`, `ec2_instance`), the `vpc_subnet_id` property must be defined and set to a valid VPC subnet ID. Tasks with `state` equal to `absent` or `list` are ignored. Resources missing `vpc_subnet_id` or with it undefined are flagged.

Secure example Ansible task:

```yaml
- name: Launch EC2 instance in VPC subnet
  amazon.aws.ec2_instance:
    name: my-instance
    image_id: ami-0123456789abcdef0
    instance_type: t3.micro
    vpc_subnet_id: subnet-0abc1234def567890
    security_groups:
      - sg-0a1b2c3d4e5f6g7h
```

## Compliant Code Examples
```yaml
- name: Start an instance and have it begin a Tower callback on boot v3
  amazon.aws.ec2_instance:
    name: tower-callback-test
    key_name: prod-ssh-key
    vpc_subnet_id: subnet-5ca1ab1e
    security_group: default
    tower_callback:
      # IP or hostname of tower server
      tower_address: 1.2.3.4
      job_template_id: 876
      host_config_key: '[secret config key goes here]'
    network:
      assign_public_ip: true
    image_id: ami-123456
    cpu_credit_specification: unlimited
    tags:
      SomeThing: A value
- name: Start an instance and have it begin a Tower callback on boot v4
  amazon.aws.ec2_instance:
    name: my-ec2-instance
    key_name: mykey
    instance_type: t2.micro
    image_id: ami-123456
    vpc_subnet_id: subnet-29e63245

```
## Non-Compliant Code Examples
```yaml
- name: Start an instance and have it begin a Tower callback on boot
  amazon.aws.ec2_instance:
    name: "tower-callback-test"
    key_name: "prod-ssh-key"
    security_group: default
    tower_callback:
      # IP or hostname of tower server
      tower_address: 1.2.3.4
      job_template_id: 876
      host_config_key: '[secret config key goes here]'
    network:
      assign_public_ip: true
    image_id: ami-123456
    cpu_credit_specification: unlimited
    tags:
      SomeThing: "A value"
- name: Start an instance and have it begin a Tower callback on boot v2
  amazon.aws.ec2_instance:
    name: my-ec2-instance
    key_name: mykey
    instance_type: t2.micro
    image_id: ami-123456

```