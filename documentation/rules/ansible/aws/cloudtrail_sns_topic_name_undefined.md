---
title: "CloudTrail SNS topic name undefined"
group_id: "Ansible / AWS"
meta:
  name: "aws/cloudtrail_sns_topic_name_undefined"
  id: "5ba316a9-c466-4ec1-8d5b-bc6107dc9a92"
  display_name: "CloudTrail SNS topic name undefined"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}5ba316a9-c466-4ec1-8d5b-bc6107dc9a92{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/cloudtrail_module.html)

### Description

CloudTrail should be configured to publish notifications to an SNS topic so trail events and log delivery issues can trigger alerts and automated responses. Without an SNS target, you may miss timely notifications about suspicious activity or failures.

For Ansible CloudTrail tasks (modules `amazon.aws.cloudtrail` or `cloudtrail`), the `sns_topic_name` property must be defined and non-null. Tasks missing `sns_topic_name` or with it set to `null`/empty are flagged. Ensure the value references an existing SNS topic (or create one in the same playbook) so CloudTrail can publish notifications.

Secure example:

```yaml
- name: Create CloudTrail with SNS notifications
  amazon.aws.cloudtrail:
    name: my-trail
    s3_bucket_name: my-cloudtrail-bucket
    sns_topic_name: my-cloudtrail-topic
    is_multi_region_trail: true
    include_global_service_events: true
    state: present
```

## Compliant Code Examples
```yaml
- name: sns topic name defined
  amazon.aws.cloudtrail:
    state: present
    name: default
    s3_bucket_name: mylogbucket
    s3_key_prefix: cloudtrail
    region: us-east-1
    sns_topic_name: some_topic_name

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
- name: sns topic name defined
  amazon.aws.cloudtrail:
    state: present
    name: default
    s3_bucket_name: mylogbucket
    s3_key_prefix: cloudtrail
    region: us-east-1
    sns_topic_name:

```