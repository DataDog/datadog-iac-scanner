---
title: "CloudTrail Logging Disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/cloudtrail_logging_disabled"
  id: "d4a73c49-cbaa-4c6f-80ee-d6ef5a3a26f5"
  display_name: "CloudTrail Logging Disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `d4a73c49-cbaa-4c6f-80ee-d6ef5a3a26f5`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/cloudtrail_module.html#parameter-enable_logging)

### Description

CloudTrail logging must be enabled to record AWS API activity for detection, auditing, and forensic investigations and to help meet compliance requirements; disabling logging can allow malicious or accidental changes to go undetected. In Ansible, tasks using the `community.aws.cloudtrail` or `cloudtrail` modules must have the `enable_logging` property set to `true`. This rule flags tasks where `enable_logging` is explicitly set to `false`; ensure the property is present and set to `true` to enable delivery of management events and logs. Example secure Ansible task:

```yaml
- name: Ensure CloudTrail logging is enabled
  community.aws.cloudtrail:
    name: my-trail
    s3_bucket_name: my-cloudtrail-bucket
    enable_logging: true
```

## Compliant Code Examples
```yaml
- name: example
  community.aws.cloudtrail:
    state: present
    name: default
    enable_logging: true

```
## Non-Compliant Code Examples
```yaml
- name: example
  community.aws.cloudtrail:
    state: present
    name: default
    enable_logging: false

```