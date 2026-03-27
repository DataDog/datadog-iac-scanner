---
title: "EFS not encrypted"
group_id: "Ansible / AWS"
meta:
  name: "aws/efs_not_encrypted"
  id: "727c4fd4-d604-4df6-a179-7713d3c85e20"
  display_name: "EFS not encrypted"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `727c4fd4-d604-4df6-a179-7713d3c85e20`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/efs_module.html#parameter-encrypt)

### Description

EFS file systems must have encryption enabled to protect data at rest and prevent exposure of file system contents, snapshots, and backups if storage media is compromised. For Ansible tasks using the `community.aws.efs` or `efs` modules, the `encrypt` property must be defined and set to `true`. Resources that omit `encrypt` or have `encrypt: false` are flagged as misconfigured. 

Secure example:

```yaml
- name: Create encrypted EFS filesystem
  community.aws.efs:
    name: my-efs
    encrypt: true
```

## Compliant Code Examples
```yaml
- name: foo
  community.aws.efs:
    state: present
    name: myTestEFS
    encrypt: yes
    tags:
      Name: myTestNameTag
      purpose: file-storage
    targets:
    - subnet_id: subnet-748c5d03
      security_groups: [sg-1a2b3c4d]
- name: foo2
  community.aws.efs:
    state: present
    name: myTestEFS
    encrypt: true
    tags:
      Name: myTestNameTag
      purpose: file-storage
    targets:
    - subnet_id: subnet-748c5d03
      security_groups: [sg-1a2b3c4d]

```
## Non-Compliant Code Examples
```yaml
---
- name: foo
  community.aws.efs:
    state: present
    name: myTestEFS
    encrypt: no
    tags:
      Name: myTestNameTag
      purpose: file-storage
    targets:
      - subnet_id: subnet-748c5d03
        security_groups: ["sg-1a2b3c4d"]
- name: foo2
  community.aws.efs:
    state: present
    name: myTestEFS
    encrypt: false
    tags:
      Name: myTestNameTag
      purpose: file-storage
    targets:
      - subnet_id: subnet-748c5d03
        security_groups: ["sg-1a2b3c4d"]
- name: foo3
  community.aws.efs:
    state: present
    name: myTestEFS
    tags:
      Name: myTestNameTag
      purpose: file-storage
    targets:
      - subnet_id: subnet-748c5d03
        security_groups: ["sg-1a2b3c4d"]

```