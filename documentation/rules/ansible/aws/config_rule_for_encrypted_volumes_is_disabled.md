---
title: "Config rule for encrypted volumes disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/config_rule_for_encrypted_volumes_is_disabled"
  id: "ansible-aws-config-rule-for-encrypted-volumes-disabled"
  display_name: "Config rule for encrypted volumes disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `ansible-aws-config-rule-for-encrypted-volumes-disabled`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/config_rule_module.html#parameter-source/identifier)

### Description

Missing an AWS Config rule for encrypted volumes prevents automated detection of unencrypted block storage and snapshots, leaving data at rest vulnerable to exposure if storage is compromised.

For Ansible-managed resources, define an `aws_config_rule` (module `community.aws.config_rule` or `aws_config_rule`) with `source.identifier` set to `ENCRYPTED_VOLUMES`. The check is case-insensitive. Tasks that omit this `aws_config_rule` or set `source.identifier` to a different value are flagged.

Secure Ansible example:

```yaml
- name: Ensure AWS Config rule for encrypted volumes exists
  community.aws.config_rule:
    name: encrypted-volumes-rule
    source:
      owner: AWS
      identifier: ENCRYPTED_VOLUMES
```

## Compliant Code Examples
```yaml
- name: foo
  community.aws.config_rule:
    name: test_config_rule
    state: present
    description: This AWS Config rule checks for public write access on S3 buckets
    scope:
      compliance_types:
      - AWS::S3::Bucket
    source:
      owner: AWS
      identifier: ENCRYPTED_VOLUMES

```
## Non-Compliant Code Examples
```yaml
---
- name: foo
  community.aws.config_rule:
    name: test_config_rule
    state: present
    description: 'This AWS Config rule checks for public write access on S3 buckets'
    scope:
      compliance_types:
        - 'AWS::S3::Bucket'
    source:
      owner: AWS
      identifier: 'S3_BUCKET_PUBLIC_WRITE_PROHIBITED'

```