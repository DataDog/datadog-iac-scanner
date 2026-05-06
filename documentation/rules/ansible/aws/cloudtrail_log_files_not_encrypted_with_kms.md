---
title: "CloudTrail log files not encrypted with KMS"
group_id: "Ansible / AWS"
meta:
  name: "aws/cloudtrail_log_files_not_encrypted_with_kms"
  id: "f5587077-3f57-4370-9b4e-4eb5b1bac85b"
  display_name: "CloudTrail log files not encrypted with KMS"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Encryption"
---
## Metadata

**Id:** {{</* copyable-code */>}}f5587077-3f57-4370-9b4e-4eb5b1bac85b{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/cloudtrail_module.html)

### Description

CloudTrail log deliveries must be encrypted with an AWS KMS customer-managed key to protect audit logs at rest and ensure strict key access control, rotation, and usage auditing. In Ansible tasks using the `amazon.aws.cloudtrail` or `cloudtrail` module, the `kms_key_id` parameter must be defined and set to a KMS key ARN or alias (for example `arn:aws:kms:region:account-id:key/KEY-ID` or `alias/my-key`).

Tasks missing `kms_key_id` are flagged. Without a customer-managed key, you lose control over key access, rotation, and usage auditing.

Secure configuration example:

```yaml
- name: Create CloudTrail with KMS encryption
  amazon.aws.cloudtrail:
    name: my-trail
    s3_bucket_name: my-cloudtrail-bucket
    kms_key_id: arn:aws:kms:us-east-1:123456789012:key/abcd1234-ef56-7890-abcd-EXAMPLE
```

## Compliant Code Examples
```yaml
- name: create multi-region trail with validation and tags v2
  amazon.aws.cloudtrail:
    state: present
    name: default
    s3_bucket_name: mylogbucket
    region: us-east-1
    is_multi_region_trail: true
    enable_log_file_validation: true
    cloudwatch_logs_role_arn: arn:aws:iam::123456789012:role/CloudTrail_CloudWatchLogs_Role
    cloudwatch_logs_log_group_arn: arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/DefaultLogGroup:*
    kms_key_id: alias/MyAliasName
    tags:
      environment: dev
      Name: default

```
## Non-Compliant Code Examples
```yaml
- name: no sns topic name
  amazon.aws.cloudtrail:
    state: present
    name: default
    s3_bucket_name: mylogbucket
    s3_key_prefix: cloudtrail
    region: us-east-1

```