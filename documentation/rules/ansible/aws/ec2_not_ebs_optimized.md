---
title: "EC2 instance is not EBS optimized"
group_id: "Ansible / AWS"
meta:
  name: "aws/ec2_not_ebs_optimized"
  id: "338b6cab-961d-4998-bb49-e5b6a11c9a5c"
  display_name: "EC2 instance is not EBS optimized"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `338b6cab-961d-4998-bb49-e5b6a11c9a5c`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_instance_module.html#parameter-ebs_optimized)

### Description

EC2 instances must be EBS-optimized to ensure consistent, high-performance EBS I/O and reduce contention between EBS traffic and other instance operations.

For Ansible EC2 tasks using the `amazon.aws.ec2_instance` or `ec2_instance` module, the `ebs_optimized` property must be defined and set to `true` for instance types that are not EBS-optimized by default. If `instance_type` is omitted, the default `t2.micro` is assumed. Instance types that are EBS-optimized by default are exempt and are not flagged. Tasks missing the `ebs_optimized` property or with `ebs_optimized: false` are reported.

Secure configuration example:

```yaml
- name: Launch EBS-optimized EC2
  amazon.aws.ec2_instance:
    name: my-instance
    instance_type: m5.large
    image_id: ami-0123456789abcdef0
    vpc_subnet_id: subnet-29e63245
    ebs_optimized: true
```

## Compliant Code Examples
```yaml
- name: Launch with ebs_optimized true
  amazon.aws.ec2_instance:
    name: app-server
    key_name: mykey
    instance_type: t2.micro
    image_id: ami-123456
    vpc_subnet_id: subnet-29e63245
    ebs_optimized: true
    network:
      assign_public_ip: false

```

```yaml
- name: Launch instance type EBS-optimized by default
  amazon.aws.ec2_instance:
    name: app-server
    key_name: mykey
    instance_type: m5.large
    image_id: ami-123456
    vpc_subnet_id: subnet-29e63245
    network:
      assign_public_ip: false

```

```yaml
- name: Launch EBS-optimized type with false
  amazon.aws.ec2_instance:
    name: app-server
    key_name: mykey
    instance_type: m5.large
    image_id: ami-123456
    vpc_subnet_id: subnet-29e63245
    ebs_optimized: false
    network:
      assign_public_ip: false

```
## Non-Compliant Code Examples
```yaml
- name: Launch t2.micro with ebs_optimized false
  amazon.aws.ec2_instance:
    name: app-server-2
    key_name: mykey
    instance_type: t2.micro
    image_id: ami-123456
    vpc_subnet_id: subnet-29e63245
    ebs_optimized: false
    network:
      assign_public_ip: false

```

```yaml
- name: Launch instance default type without ebs_optimized
  amazon.aws.ec2_instance:
    name: app-server-3
    key_name: mykey
    image_id: ami-123456
    vpc_subnet_id: subnet-29e63245
    network:
      assign_public_ip: false

```

```yaml
- name: Launch t2.micro without ebs_optimized
  amazon.aws.ec2_instance:
    name: app-server
    key_name: mykey
    instance_type: t2.micro
    image_id: ami-123456
    vpc_subnet_id: subnet-29e63245
    network:
      assign_public_ip: false

```