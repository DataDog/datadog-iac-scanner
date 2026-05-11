---
title: "SQS policy allows all actions"
group_id: "Ansible / AWS"
meta:
  name: "aws/sqs_policy_allows_all_actions"
  id: "ansible-aws-sqs-policy-allows-all-actions"
  display_name: "SQS policy allows all actions"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `ansible-aws-sqs-policy-allows-all-actions`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/sqs_queue_module.html)

### Description

SQS queue policies must not grant wildcard (`*`) actions. Allowing all actions on a queue enables unauthorized access, message retrieval or deletion, and queue modification, which can lead to data exposure or service disruption.

For Ansible SQS resources (`community.aws.sqs_queue` and `sqs_queue`), inspect the `policy` document and ensure no `Statement` with `Effect: "Allow"` has `Action` set to `*` or contains `*`. Resources with `Action` set to `*` or `Action` arrays that include `*` are flagged. Instead, specify explicit SQS actions (for example, `sqs:SendMessage`, `sqs:ReceiveMessage`, `sqs:DeleteMessage`) and restrict principals to the minimum required.

Secure example with explicit actions and principal:

```yaml
- name: Create SQS queue with restricted policy
  community.aws.sqs_queue:
    name: my-queue
    policy: |
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Principal": { "AWS": "arn:aws:iam::123456789012:role/MyRole" },
            "Action": ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage"],
            "Resource": "arn:aws:sqs:us-east-1:123456789012:my-queue"
          }
        ]
      }
```

## Compliant Code Examples
```yaml
- name: Create SQS queue with redrive policy
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
      Statement:
      - Effect: Allow
        Action: logs:CreateLogGroup
        Resource: '*'
    make_default: false
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: Second SQS queue with policy
  community.aws.sqs_queue:
    name: my-queue2
    region: ap-southeast-3
    default_visibility_timeout: 120
    message_retention_period: 86400
    maximum_message_size: 1024
    delivery_delay: 30
    receive_message_wait_time: 20
    policy:
      Version: "2012-10-17"
      Statement:
      - Effect: "Allow"
        Action: "aws:action"
        Resource: "*"
      - Effect: "Allow"
        Action: "*"
        Resource: "*"
    make_default: false
    state: present

```