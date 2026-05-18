---
title: "API Gateway with CloudWatch Logs disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/api_gateway_with_cloudwatch_logging_disabled"
  id: "ansible-aws-api-gateway-with-cloudwatch-logging-disabled"
  display_name: "API Gateway with CloudWatch Logs disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-api-gateway-with-cloudwatch-logging-disabled{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/cloudwatchlogs_log_group_module.html#ansible-collections-community-aws-cloudwatchlogs-log-group-module)

### Description

APIs must send request logs and execution traces to CloudWatch Logs so activity, errors, and suspicious behavior can be detected and investigated. Without a configured log group, you lose critical visibility for incident response and troubleshooting.

In Ansible, tasks using the `amazon.aws.cloudwatchlogs_log_group` or `cloudwatchlogs_log_group` modules must include the `log_group_name` property to create or reference a specific CloudWatch Logs group. Tasks missing `log_group_name` (or with it unset) are flagged. Set `log_group_name` to a stable, descriptive string and ensure API Gateway access logging or tracing is pointed to that group.

Secure configuration example:

```yaml
- name: Create CloudWatch log group for API Gateway
  amazon.aws.cloudwatchlogs_log_group:
    log_group_name: "/aws/apigateway/my-api"
    state: present
    retention_in_days: 30
```

## Compliant Code Examples
```yaml
- name: Setup AWS API Gateway setup on AWS cloudwatchlogs
  amazon.aws.cloudwatchlogs_log_group:
    state: present
    log_group_name: test-log-group
    tags: {Name: test-log-group, Env: QA}
    kms_key_id: arn:aws:kms:region:account-id:key/key-id

```
## Non-Compliant Code Examples
```yaml
---
- name: Setup AWS API Gateway setup on AWS cloudwatchlogs
  amazon.aws.cloudwatchlogs_log_group:
    state: present
    kms_key_id: arn:aws:kms:region:account-id:key/key-id

```