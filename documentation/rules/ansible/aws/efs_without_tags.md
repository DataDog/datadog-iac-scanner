---
title: "EFS without tags"
group_id: "Ansible / AWS"
meta:
  name: "aws/efs_without_tags"
  id: "b8a9852c-9943-4973-b8d5-77dae9352851"
  display_name: "EFS without tags"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `b8a9852c-9943-4973-b8d5-77dae9352851`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/efs_module.html)

### Description

EFS filesystems must have tags defined to support asset identification, tag-based access control, cost allocation, and automated lifecycle or compliance policies. For Ansible tasks using the `community.aws.efs` or `efs` modules, the `tags` property must be present and contain at least one key/value pair. Tasks that omit the `tags` property or provide an empty mapping are flagged as missing required metadata.

Secure example:

```yaml
- name: Create EFS filesystem
  community.aws.efs:
    state: present
    name: my-efs
    performance_mode: generalPurpose
    tags:
      Name: my-efs
      Environment: production
```

## Compliant Code Examples
```yaml
- name: EFS provisioning
  community.aws.efs:
    state: present
    name: myTestEFS
    tags:
      Name: myTestNameTag
      purpose: file-storage
    targets:
      - subnet_id: subnet-748c5d03
        security_groups: [ "sg-1a2b3c4d" ]

```
## Non-Compliant Code Examples
```yaml
- name: EFS provisioning without tags
  community.aws.efs:
    state: present
    name: myTestEFS
    targets:
      - subnet_id: subnet-748c5d03
        security_groups: [ "sg-1a2b3c4d" ]

```