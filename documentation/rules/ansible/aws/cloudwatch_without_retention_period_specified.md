---
title: "CloudWatch without retention period specified"
group_id: "Ansible / AWS"
meta:
  name: "aws/cloudwatch_without_retention_period_specified"
  id: "ansible-aws-cloudwatch-without-retention-period-specified"
  display_name: "CloudWatch without retention period specified"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `ansible-aws-cloudwatch-without-retention-period-specified`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/cloudwatchlogs_log_group_module.html)

### Description

CloudWatch Log Groups must have a defined retention period to retain logs for incident investigation and regulatory compliance. Without one, indefinite retention increases storage costs and the risk of long-term data exposure.

For Ansible tasks using `amazon.aws.cloudwatchlogs_log_group` or `cloudwatchlogs_log_group`, the `retention` property must be set to one of the AWS-supported retention periods: [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653]. Resources missing `retention` or with a value not in this list are flagged as misconfigured.

Secure configuration example:

```
- name: Create CloudWatch log group with retention
  amazon.aws.cloudwatchlogs_log_group:
    name: my-log-group
    retention: 365
```

## Compliant Code Examples
```yaml
- name: example3 ec2 group
  amazon.aws.cloudwatchlogs_log_group:
    log_group_name: test-log-group
    retention: 5

```
## Non-Compliant Code Examples
```yaml
- name: example ec2 group
  amazon.aws.cloudwatchlogs_log_group:
    log_group_name: test-log-group
- name: example2 ec2 group
  amazon.aws.cloudwatchlogs_log_group:
    log_group_name: test-log-group
    retention: 111111

```