---
title: "EBS volume encryption disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/ebs_volume_encryption_disabled"
  id: "ansible-aws-ebs-volume-encryption-disabled"
  display_name: "EBS volume encryption disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-ebs-volume-encryption-disabled{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_vol_module.html#parameter-encrypted)

### Description

Encrypt EBS volumes to protect data at rest and ensure snapshots and backups are also encrypted. Unencrypted volumes and their snapshots risk exposure if storage media or backups are compromised. For Ansible, tasks using the `amazon.aws.ec2_vol` or legacy `ec2_vol` modules must define the `encrypted` property and set it to `true` (or `yes`). Tasks with `state` set to `absent` or `list` are ignored. Resources with `encrypted` set to `false` or missing the `encrypted` attribute are flagged.

Secure Ansible example:

```yaml
- name: Create encrypted EBS volume
  amazon.aws.ec2_vol:
    volume_size: 10
    region: us-east-1
    encrypted: yes
```

## Compliant Code Examples
```yaml
- name: Creating EBS volume05
  amazon.aws.ec2_vol:
    name: my-volume
    instance: XXXXXX
    encrypted: yes
    volume_size: 50
    volume_type: gp2
    device_name: /dev/xvdf
- name: Creating EBS volume06
  amazon.aws.ec2_vol:
    name: my-volume
    instance: XXXXXX
    encrypted: 'True'
    volume_size: 50
    volume_type: gp2
    device_name: /dev/xvdf

```
## Non-Compliant Code Examples
```yaml
---
- name: Creating EBS volume01
  amazon.aws.ec2_vol:
    name: my-volume
    instance: XXXXXX
    encrypted: no
    volume_size: 50
    volume_type: gp2
    device_name: /dev/xvdf
- name: Creating EBS volume02
  amazon.aws.ec2_vol:
    name: my-volume
    instance: XXXXXX
    encrypted: false
    volume_size: 50
    volume_type: gp2
    device_name: /dev/xvdf
- name: Creating EBS volume03
  amazon.aws.ec2_vol:
    name: my-volume
    instance: XXXXXX
    encrypted: "false"
    volume_size: 50
    volume_type: gp2
    device_name: /dev/xvdf
- name: Creating EBS volume04
  amazon.aws.ec2_vol:
    name: my-volume
    instance: XXXXXX
    volume_size: 50
    volume_type: gp2
    device_name: /dev/xvdf

```