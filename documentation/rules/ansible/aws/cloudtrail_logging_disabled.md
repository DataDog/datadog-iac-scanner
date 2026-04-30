---
title: "CloudTrail logging disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/cloudtrail_logging_disabled"
  id: "ansible-aws-cloudtrail-logging-disabled"
  display_name: "CloudTrail logging disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `ansible-aws-cloudtrail-logging-disabled`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/cloudtrail_module.html#parameter-enable_logging)

### Description

CloudTrail logging must be enabled to record AWS API activity for detection, auditing, and forensic investigations, and to meet compliance requirements. Disabling logging can allow malicious or accidental changes to go undetected.

In Ansible, tasks using the `amazon.aws.cloudtrail` or `cloudtrail` modules must have the `enable_logging` property set to `true`. This rule flags tasks where `enable_logging` is explicitly set to `false`. Ensure the property is present and set to `true` to enable delivery of management events and logs. Example secure Ansible task:

```yaml
- name: Ensure CloudTrail logging is enabled
  amazon.aws.cloudtrail:
    name: my-trail
    s3_bucket_name: my-cloudtrail-bucket
    enable_logging: true
```

## Compliant Code Examples
```yaml
- name: example
  amazon.aws.cloudtrail:
    state: present
    name: default
    enable_logging: true

```
## Non-Compliant Code Examples
```yaml
- name: example
  amazon.aws.cloudtrail:
    state: present
    name: default
    enable_logging: false

```