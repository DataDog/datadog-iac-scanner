---
title: "CloudTrail log file validation disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/cloudtrail_log_file_validation_disabled"
  id: "4d8681a2-3d30-4c89-8070-08acd142748e"
  display_name: "CloudTrail log file validation disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** {{</* copyable-code */>}}4d8681a2-3d30-4c89-8070-08acd142748e{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/cloudtrail_module.html)

### Description

CloudTrail log file validation must be enabled to detect tampering of delivered log files and preserve the integrity of audit data used for incident response and compliance.

For Ansible tasks using the `amazon.aws.cloudtrail` or `cloudtrail` module, one of the properties `enable_log_file_validation` or `log_file_validation_enabled` must be defined and set to `true` (or `yes`). Resources missing both properties or with these properties set to `false`, `no`, or any non-`true` value are flagged as insecure.

Secure Ansible example:

```yaml
- name: Create CloudTrail with log file validation enabled
  amazon.aws.cloudtrail:
    name: my-trail
    s3_bucket_name: my-trail-bucket
    enable_log_file_validation: true
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
- name: create multi-region trail with validation and tags v3
  amazon.aws.cloudtrail:
    state: present
    name: default
    s3_bucket_name: mylogbucket
    region: us-east-1
    is_multi_region_trail: true
    log_file_validation_enabled: true
    cloudwatch_logs_role_arn: arn:aws:iam::123456789012:role/CloudTrail_CloudWatchLogs_Role
    cloudwatch_logs_log_group_arn: arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/DefaultLogGroup:*
    kms_key_id: alias/MyAliasName
    tags:
      environment: dev
      Name: default

```
## Non-Compliant Code Examples
```yaml
- name: create multi-region trail with validation and tags
  amazon.aws.cloudtrail:
    state: present
    name: default
    s3_bucket_name: mylogbucket
    region: us-east-1
    is_multi_region_trail: true
    cloudwatch_logs_role_arn: "arn:aws:iam::123456789012:role/CloudTrail_CloudWatchLogs_Role"
    cloudwatch_logs_log_group_arn: "arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/DefaultLogGroup:*"
    kms_key_id: "alias/MyAliasName"
    tags:
      environment: dev
      Name: default
- name: create multi-region trail with validation and tags v7
  amazon.aws.cloudtrail:
    state: present
    name: default
    s3_bucket_name: mylogbucket
    region: us-east-1
    is_multi_region_trail: true
    enable_log_file_validation: false
    cloudwatch_logs_role_arn: "arn:aws:iam::123456789012:role/CloudTrail_CloudWatchLogs_Role"
    cloudwatch_logs_log_group_arn: "arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/DefaultLogGroup:*"
    kms_key_id: "alias/MyAliasName"
    tags:
      environment: dev
      Name: default

```