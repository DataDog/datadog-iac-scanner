---
title: "EFS without KMS"
group_id: "Ansible / AWS"
meta:
  name: "aws/efs_without_kms"
  id: "ansible-aws-efs-without-kms"
  display_name: "EFS without KMS"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Encryption"
---
## Metadata

**Id:** `ansible-aws-efs-without-kms`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/efs_module.html#parameter-kms_key_id)

### Description

EFS filesystems should be encrypted with a customer-managed AWS KMS CMK to protect data at rest and maintain control over key rotation, access policies, and audit logging.

In Ansible, the `kms_key_id` option on the `community.aws.efs` (or legacy `efs`) module must be defined and set to a customer-managed key identifier (KMS key ID, key ARN, or alias) rather than relying on the AWS-managed key. Tasks that omit `kms_key_id` or leave it undefined default to an AWS-managed key and are flagged by this rule.

Secure configuration example:

```yaml
- name: Create encrypted EFS filesystem
  community.aws.efs:
    name: my-efs
    performance_mode: generalPurpose
    kms_key_id: arn:aws:kms:us-east-1:123456789012:key/abcdef12-3456-7890-abcd-ef1234567890
    state: present
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
    kms_key_id: "some-key-id"

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

```