---
title: "AMI Not Encrypted"
group_id: "Ansible / AWS"
meta:
  name: "aws/ami_not_encrypted"
  id: "97707503-a22c-4cd7-b7c0-f088fa7cf830"
  display_name: "AMI Not Encrypted"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `97707503-a22c-4cd7-b7c0-f088fa7cf830`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_ami_module.html)

### Description

AMIs must have their block device mappings encrypted to protect data at rest and prevent sensitive information from being exposed if snapshots are copied, shared, or recovered on different storage. For Ansible tasks using the `amazon.aws.ec2_ami` or `ec2_ami` modules, each entry in the `device_mapping` must include `encrypted: true`; resources missing the `encrypted` attribute or with `encrypted: false` will be flagged. Ensure every device mapping explicitly sets `encrypted: true` so AMI snapshots and derived volumes remain encrypted.

Secure configuration example:

```yaml
- name: Create AMI with encrypted device mapping
  amazon.aws.ec2_ami:
    name: my-encrypted-ami
    device_mapping:
      - device_name: /dev/sda1
        encrypted: true
```

## Compliant Code Examples
```yaml
- name: Basic AMI Creation
  amazon.aws.ec2_ami:
    instance_id: i-xxxxxx
    device_mapping:
      device_name: /dev/sda
      encrypted: yes
    wait: yes
    name: newtest
    tags:
      Name: newtest
      Service: TestService

```
## Non-Compliant Code Examples
```yaml
- name: Basic AMI Creation
  amazon.aws.ec2_ami:
    instance_id: i-xxxxxx
    device_mapping:
      device_name: /dev/sda
      encrypted: no
    wait: yes
    name: newtest
    tags:
      Name: newtest
      Service: TestService
- name: Basic AMI Creation2
  amazon.aws.ec2_ami:
    instance_id: i-xxxxxx
    device_mapping:
      device_name: /dev/sda
    wait: yes
    name: newtest
    tags:
      Name: newtest
      Service: TestService

```