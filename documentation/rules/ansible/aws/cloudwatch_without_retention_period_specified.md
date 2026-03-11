---
title: "CloudWatch Without Retention Period Specified"
group_id: "Ansible / AWS"
meta:
  name: "aws/cloudwatch_without_retention_period_specified"
  id: "e24e18d9-4c2b-4649-b3d0-18c088145e24"
  display_name: "CloudWatch Without Retention Period Specified"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `e24e18d9-4c2b-4649-b3d0-18c088145e24`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/cloudwatchlogs_log_group_module.html)

### Description

CloudWatch Log Groups must have a defined retention period to retain logs for incident investigation and regulatory compliance and to avoid indefinite retention that increases storage costs and risk of long‑term data exposure. For Ansible tasks using `community.aws.cloudwatchlogs_log_group` or `cloudwatchlogs_log_group`, the `retention` property must be set and its value must be one of the AWS-supported retention periods: [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653]. Resources missing `retention` or with a value not in this list will be flagged as misconfigured.  

Secure configuration example:

```
- name: Create CloudWatch log group with retention
  community.aws.cloudwatchlogs_log_group:
    name: my-log-group
    retention: 365
```

## Compliant Code Examples
```yaml
- name: example3 ec2 group
  community.aws.cloudwatchlogs_log_group:
    log_group_name: test-log-group
    retention: 5

```
## Non-Compliant Code Examples
```yaml
- name: example ec2 group
  community.aws.cloudwatchlogs_log_group:
    log_group_name: test-log-group
- name: example2 ec2 group
  community.aws.cloudwatchlogs_log_group:
    log_group_name: test-log-group
    retention: 111111

```