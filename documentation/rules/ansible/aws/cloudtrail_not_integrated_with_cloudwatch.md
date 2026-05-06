---
title: "CloudTrail not integrated with CloudWatch"
group_id: "Ansible / AWS"
meta:
  name: "aws/cloudtrail_not_integrated_with_cloudwatch"
  id: "ebb2118a-03bc-4d53-ab43-d8750f5cb8d3"
  display_name: "CloudTrail not integrated with CloudWatch"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** {{</* copyable-code */>}}ebb2118a-03bc-4d53-ab43-d8750f5cb8d3{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/cloudtrail_module.html)

### Description

CloudTrail must be integrated with CloudWatch Logs so events are available for real-time detection, alerting, and centralized log analysis, and so forensic evidence is retained for incident investigation.

For Ansible tasks using the `amazon.aws.cloudtrail` or `cloudtrail` modules, the `cloudwatch_logs_role_arn` and `cloudwatch_logs_log_group_arn` properties must be defined. `cloudwatch_logs_role_arn` should be an IAM role ARN that allows CloudTrail to publish to CloudWatch Logs. `cloudwatch_logs_log_group_arn` should reference the destination Log Group ARN. Tasks missing either property are flagged.

Secure configuration example:

```yaml
- name: Create CloudTrail with CloudWatch Logs integration
  amazon.aws.cloudtrail:
    name: my-trail
    s3_bucket_name: my-bucket
    is_multi_region_trail: yes
    cloudwatch_logs_role_arn: arn:aws:iam::123456789012:role/CloudTrail_CloudWatch_Logs_Role
    cloudwatch_logs_log_group_arn: arn:aws:logs:us-east-1:123456789012:log-group:/aws/cloudtrail
```

## Compliant Code Examples
```yaml
- name: create multi-region trail with validation and tags negative
  amazon.aws.cloudtrail:
    state: present
    name: default
    s3_bucket_name: mylogbucket
    region: us-east-1
    is_multi_region_trail: true
    enable_log_file_validation: true
    cloudwatch_logs_role_arn: "arn:aws:iam::123456789012:role/CloudTrail_CloudWatchLogs_Role"
    cloudwatch_logs_log_group_arn: "arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/DefaultLogGroup:*"
    kms_key_id: "alias/MyAliasName"
    tags:
      environment: dev
      Name: default

```
## Non-Compliant Code Examples
```yaml
- name: positive1
  amazon.aws.cloudtrail:
    state: present
    name: default
    s3_bucket_name: mylogbucket
    region: us-east-1
    is_multi_region_trail: true
    enable_log_file_validation: true
    kms_key_id: "alias/MyAliasName"
    tags:
      environment: dev
      Name: default
- name: positive2
  amazon.aws.cloudtrail:
    state: present
    name: default
    s3_bucket_name: mylogbucket
    region: us-east-1
    is_multi_region_trail: true
    enable_log_file_validation: true
    cloudwatch_logs_role_arn: "arn:aws:iam::123456789012:role/CloudTrail_CloudWatchLogs_Role"
    kms_key_id: "alias/MyAliasName"
    tags:
      environment: dev
      Name: default
- name: positive3
  amazon.aws.cloudtrail:
    state: present
    name: default
    s3_bucket_name: mylogbucket
    region: us-east-1
    is_multi_region_trail: true
    enable_log_file_validation: true
    cloudwatch_logs_log_group_arn: "arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/DefaultLogGroup:*"
    kms_key_id: "alias/MyAliasName"
    tags:
      environment: dev
      Name: default

```