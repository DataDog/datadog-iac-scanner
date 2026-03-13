---
title: "SQS queue exposed"
group_id: "Ansible / AWS"
meta:
  name: "aws/sqs_queue_exposed"
  id: "86b0efa7-4901-4edd-a37a-c034bec6645a"
  display_name: "SQS queue exposed"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `86b0efa7-4901-4edd-a37a-c034bec6645a`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/sqs_queue_module.html#parameter-policy)

### Description

Granting the wildcard principal (`*`) `Allow` access in an SQS queue policy makes the queue publicly accessible. Unauthorized users or principals can send, receive, or modify messages, increasing the risk of data exposure and message injection.

For Ansible SQS tasks (modules `community.aws.sqs_queue` or `sqs_queue`), inspect the `policy` property and ensure no policy Statement has `"Effect": "Allow"` with `"Principal": "*"`. Statements must specify explicit principals (for example AWS account ARNs) or include restrictive conditions.

Resources with policy statements where `Principal == "*" ` and `Effect == "Allow"` are flagged. Replace wildcard principals with explicit ARNs or add conditions such as `aws:SourceAccount` or `aws:SourceVpce` to restrict access.

Secure example (Ansible task with explicit principal):

```yaml
- name: Create SQS queue with restricted policy
  community.aws.sqs_queue:
    name: my-queue
    policy: |
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Sid": "AllowSpecificAccount",
            "Effect": "Allow",
            "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
            "Action": ["SQS:SendMessage", "SQS:ReceiveMessage"],
            "Resource": "arn:aws:sqs:us-east-1:123456789012:my-queue"
          }
        ]
      }
```

## Compliant Code Examples
```yaml
- name: example
  community.aws.sqs_queue:
    name: my-queue
    region: ap-southeast-2
    default_visibility_timeout: 120
    message_retention_period: 86400
    maximum_message_size: 1024
    delivery_delay: 30
    receive_message_wait_time: 20
    policy:
      Version: '2012-10-17'
      Id: sqspolicy
      Statement:
        Sid: First
        Effect: Allow
        Action: sqs:SendMessage
        Resource: ${aws_sqs_queue.q.arn}
        Condition:
          ArnEquals:
          aws:SourceArn: ${aws_sns_topic.example.arn}

```
## Non-Compliant Code Examples
```yaml
- name: example
  community.aws.sqs_queue:
    name: my-queue
    region: ap-southeast-2
    default_visibility_timeout: 120
    message_retention_period: 86400
    maximum_message_size: 1024
    delivery_delay: 30
    receive_message_wait_time: 20
    policy:
      Version: '2012-10-17'
      Id: sqspolicy
      Statement:
        Sid: First
        Effect: Allow
        Principal: '*'
        Action: sqs:SendMessage
        Resource: ${aws_sqs_queue.q.arn}
        Condition:
          ArnEquals:
          aws:SourceArn: ${aws_sns_topic.example.arn}
- name: example with list
  community.aws.sqs_queue:
    name: my-queue12
    region: ap-southeast-1
    default_visibility_timeout: 120
    message_retention_period: 86400
    maximum_message_size: 1024
    delivery_delay: 30
    receive_message_wait_time: 20
    policy:
      Version: "2012-10-17"
      Statement:
      - Effect: "Allow"
        Action: "sqs:*"
        Resource: "*"
        Principal: "*"
    make_default: false
    state: present

```