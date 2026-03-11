---
title: "EC2 Not EBS Optimized"
group_id: "Ansible / AWS"
meta:
  name: "aws/ec2_not_ebs_optimized"
  id: "338b6cab-961d-4998-bb49-e5b6a11c9a5c"
  display_name: "EC2 Not EBS Optimized"
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

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_module.html#parameter-ebs_optimized)

### Description

EC2 instances must be EBS-optimized to ensure consistent, high-performance EBS I/O and to reduce contention between EBS traffic and other instance operations. For Ansible EC2 tasks using the amazon.aws.ec2 or ec2 module, the `ebs_optimized` property must be defined and set to `true` for instance types that are not EBS-optimized by default. If `instance_type` is omitted the default `t2.micro` is assumed; instance types that are EBS-optimized by default are exempt and will not be flagged. Tasks missing the `ebs_optimized` property or with `ebs_optimized: false` will be reported.

Secure configuration example:

```yaml
- name: Launch EBS-optimized EC2
  amazon.aws.ec2:
    instance_type: m5.large
    image: ami-0123456789abcdef0
    ebs_optimized: true
```

## Compliant Code Examples
```yaml
- name: example4
  amazon.aws.ec2:
    key_name: mykey
    image: ami-123456
    wait: yes
    group: my_sg
    count: 3
    vpc_subnet_id: subnet-29e63245
    ebs_optimized: true

```

```yaml
- name: example5
  amazon.aws.ec2:
    key_name: mykey
    instance_type: t3.nano
    image: ami-123456
    wait: yes
    group: my_sg
    count: 3
    vpc_subnet_id: subnet-29e63245

```

```yaml
- name: example5
  amazon.aws.ec2:
    key_name: mykey
    instance_type: t3.nano
    image: ami-123456
    wait: yes
    group: my_sg
    count: 3
    vpc_subnet_id: subnet-29e63245
    ebs_optimized: false

```
## Non-Compliant Code Examples
```yaml
- name: example2
  amazon.aws.ec2:
    key_name: mykey
    instance_type: t2.micro
    image: ami-123456
    wait: yes
    group: default
    count: 3
    vpc_subnet_id: subnet-29e63245
    ebs_optimized: false

```

```yaml
- name: example3
  amazon.aws.ec2:
    key_name: mykey
    image: ami-123456
    wait: yes
    group: default
    count: 3
    vpc_subnet_id: subnet-29e63245

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

```