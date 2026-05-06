---
title: "ECR image tag not immutable"
group_id: "Ansible / AWS"
meta:
  name: "aws/ecr_image_tag_not_immutable"
  id: "60bfbb8a-c72f-467f-a6dd-a46b7d612789"
  display_name: "ECR image tag not immutable"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{</* copyable-code */>}}60bfbb8a-c72f-467f-a6dd-a46b7d612789{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/ecs_ecr_module.html)

### Description

ECR repositories should enforce immutable image tags to prevent tags from being overwritten. Allowing mutable tags can enable accidental or malicious replacement of images, facilitating supply-chain tampering or execution of unexpected code. For Ansible tasks using the `community.aws.ecs_ecr` or `ecs_ecr` modules, the `image_tag_mutability` property must be defined and set to the literal string `"immutable"`. Resources missing this property or set to any other value are flagged.

Secure Ansible task example:

```yaml
- name: Create ECR repository with immutable tags
  community.aws.ecs_ecr:
    name: my-repo
    image_tag_mutability: immutable
    state: present
```

## Compliant Code Examples
```yaml
- name: create immutable ecr-repo v4
  community.aws.ecs_ecr:
    name: super/cool
    image_tag_mutability: immutable

```
## Non-Compliant Code Examples
```yaml
- name: create immutable ecr-repo
  community.aws.ecs_ecr:
    name: super/cool
- name: create immutable ecr-repo v2
  community.aws.ecs_ecr:
    name: super/cool
    image_tag_mutability: mutable

```