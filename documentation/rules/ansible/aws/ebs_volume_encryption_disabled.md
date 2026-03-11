---
title: "EBS Volume Encryption Disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/ebs_volume_encryption_disabled"
  id: "4b6012e7-7176-46e4-8108-e441785eae57"
  display_name: "EBS Volume Encryption Disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `4b6012e7-7176-46e4-8108-e441785eae57`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_vol_module.html#parameter-encrypted)

### Description

EBS volumes must be encrypted to protect data at rest and to ensure snapshots and backups are also encrypted; unencrypted volumes and their snapshots can be exposed if storage media or backups are compromised. For Ansible, tasks using the `amazon.aws.ec2_vol` or legacy `ec2_vol` modules must define the `encrypted` property and set it to `true` (or `yes`). Tasks where `state` is `absent` or `list` are ignored; resources with `encrypted=false` or missing the `encrypted` attribute will be flagged.  

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
    instance: XXXXXX
    encrypted: yes
    volume_size: 50
    volume_type: gp2
    device_name: /dev/xvdf
- name: Creating EBS volume06
  amazon.aws.ec2_vol:
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
    instance: XXXXXX
    encrypted: no
    volume_size: 50
    volume_type: gp2
    device_name: /dev/xvdf
- name: Creating EBS volume02
  amazon.aws.ec2_vol:
    instance: XXXXXX
    encrypted: false
    volume_size: 50
    volume_type: gp2
    device_name: /dev/xvdf
- name: Creating EBS volume03
  amazon.aws.ec2_vol:
    instance: XXXXXX
    encrypted: "false"
    volume_size: 50
    volume_type: gp2
    device_name: /dev/xvdf
- name: Creating EBS volume04
  amazon.aws.ec2_vol:
    instance: XXXXXX
    volume_size: 50
    volume_type: gp2
    device_name: /dev/xvdf

```