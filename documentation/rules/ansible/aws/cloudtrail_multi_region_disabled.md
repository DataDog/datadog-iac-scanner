---
title: "CloudTrail multi-region is disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/cloudtrail_multi_region_disabled"
  id: "6ad087d7-a509-4b20-b853-9ef6f5ebaa98"
  display_name: "CloudTrail multi-region is disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}6ad087d7-a509-4b20-b853-9ef6f5ebaa98{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/cloudtrail_module.html#parameter-is_multi_region_trail)

### Description

CloudTrail must be configured as a multi-region trail so that API activity across all AWS regions is captured. This ensures comprehensive auditing and timely incident response. Without multi-region logging, cross-region activity can be missed, hindering detection, forensics, and compliance.

For Ansible CloudTrail resources (modules `amazon.aws.cloudtrail` or `cloudtrail`), the `is_multi_region_trail` property must be defined and set to `true`. Resources that omit `is_multi_region_trail` or have `is_multi_region_trail: false` are flagged.

Secure example (Ansible):

```yaml
- name: Create multi-region CloudTrail
  amazon.aws.cloudtrail:
    name: my-trail
    s3_bucket_name: my-trail-bucket
    is_multi_region_trail: true
    state: present
```

## Compliant Code Examples
```yaml
- name: example1
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
- name: example1
  amazon.aws.cloudtrail:
    state: present
    name: default
    s3_bucket_name: mylogbucket
    region: us-east-1
    is_multi_region_trail: false
    enable_log_file_validation: true
    cloudwatch_logs_role_arn: "arn:aws:iam::123456789012:role/CloudTrail_CloudWatchLogs_Role"
    cloudwatch_logs_log_group_arn: "arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/DefaultLogGroup:*"
    kms_key_id: "alias/MyAliasName"
    tags:
      environment: dev
      Name: default

```