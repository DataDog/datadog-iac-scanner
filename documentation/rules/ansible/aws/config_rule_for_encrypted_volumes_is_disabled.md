---
title: "Config Rule For Encrypted Volumes Disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/config_rule_for_encrypted_volumes_is_disabled"
  id: "7674a686-e4b1-4a95-83d4-1fd53c623d84"
  display_name: "Config Rule For Encrypted Volumes Disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `7674a686-e4b1-4a95-83d4-1fd53c623d84`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/aws_config_rule_module.html#parameter-source/identifier)

### Description

Missing an AWS Config rule for encrypted volumes prevents automated detection of unencrypted block storage and snapshots, leaving data at rest vulnerable to exposure if storage is compromised. For Ansible-managed resources you must define an `aws_config_rule` (module `community.aws.aws_config_rule` or `aws_config_rule`) whose `source.identifier` is set to `ENCRYPTED_VOLUMES`. The check is case-insensitive; tasks that omit this aws_config_rule or set `source.identifier` to a different value will be flagged.

Secure Ansible example:

```yaml
- name: Ensure AWS Config rule for encrypted volumes exists
  community.aws.aws_config_rule:
    name: encrypted-volumes-rule
    source:
      owner: AWS
      identifier: ENCRYPTED_VOLUMES
```

## Compliant Code Examples
```yaml
- name: foo
  community.aws.aws_config_rule:
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
  community.aws.aws_config_rule:
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