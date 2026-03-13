---
title: "User data contains encoded private key"
group_id: "Ansible / AWS"
meta:
  name: "aws/user_data_contains_encoded_private_key"
  id: "c09f4d3e-27d2-4d46-9453-abbe9687a64e"
  display_name: "User data contains encoded private key"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `c09f4d3e-27d2-4d46-9453-abbe9687a64e`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/ec2_lc_module.html)

### Description

Embedding base64-encoded private keys in EC2 launch configuration user data exposes sensitive credentials that can be decoded and used to impersonate instances or access private services, resulting in credential compromise and lateral movement.

This rule inspects Ansible tasks using the `community.aws.ec2_lc` or `ec2_lc` modules and flags the `user_data` property when it contains the base64 prefix `LS0tLS1CR`, which corresponds to the start of an RSA private key header (`-----BEGIN R...`).

Remove any private keys from `user_data` and instead store secrets in a secure secrets manager or fetch them at runtime using instance IAM roles. Tasks embedding keys are flagged.

## Compliant Code Examples
```yaml
- name: note that encrypted volumes are only supported in >= Ansible 2.4
  community.aws.ec2_lc:
    name: special
    image_id: ami-XXX
    key_name: default
    security_groups: [group, group2]
    instance_type: t1.micro
    user_data: dGVzdA==
    volumes:
    - device_name: /dev/sda1
      volume_size: 100
      volume_type: io1
      iops: 3000
      delete_on_termination: true
      encrypted: true
    - device_name: /dev/sdb
      ephemeral: ephemeral0
- name: note that encrypted volumes are only supported in >= Ansible 2.4.2
  community.aws.ec2_lc:
    name: special2
    image_id: ami-XXX
    key_name: default
    security_groups: [group, group2]
    instance_type: t1.micro
    user_data:
    volumes:
    - device_name: /dev/sda1
      volume_size: 100
      volume_type: io1
      iops: 3000
      delete_on_termination: true
      encrypted: true
    - device_name: /dev/sdb
      ephemeral: ephemeral0

```
## Non-Compliant Code Examples
```yaml
---
- name: note that encrypted volumes are only supported in >= Ansible 2.4
  community.aws.ec2_lc:
    name: special
    image_id: ami-XXX
    key_name: default
    security_groups: ['group', 'group2' ]
    instance_type: t1.micro
    user_data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpzb21lS2V5
    volumes:
    - device_name: /dev/sda1
      volume_size: 100
      volume_type: io1
      iops: 3000
      delete_on_termination: true
      encrypted: true
    - device_name: /dev/sdb
      ephemeral: ephemeral0

```