---
title: "SQS policy with public access"
group_id: "Ansible / AWS"
meta:
  name: "aws/sqs_policy_with_public_access"
  id: "ansible-aws-sqs-policy-with-public-access"
  display_name: "SQS policy with public access"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-sqs-policy-with-public-access{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/sqs_queue_module.html)

### Description

SQS queue policies must not grant Allow permissions to a wildcard principal (`*`) combined with wildcard actions, as this gives any principal unrestricted ability to send, receive, delete, or otherwise manipulate queue messages, risking data exposure, message loss, or unauthorized message injection. In Ansible tasks using the `community.aws.sqs_queue` or `sqs_queue` module, inspect the `policy` property for policy statements where `Effect` is `"Allow"`, `Principal` is `"*"` (either `Principal == "*"` or `Principal.AWS` contains `"*"`), and `Action` contains `"*"`. Such statements are flagged.

Define explicit principals (AWS account ARNs, IAM role/user ARNs, or service principals) and restrict `Action` to the minimal SQS actions required (for example, `sqs:SendMessage`, `sqs:ReceiveMessage`). You can optionally add conditions (source ARN/IP, VPC) to further limit access.

Secure configuration example:

```yaml
- name: Create SQS queue with restricted policy
  community.aws.sqs_queue:
    name: my-queue
    policy:
      Version: "2012-10-17"
      Statement:
        - Sid: AllowSpecificAccount
          Effect: Allow
          Principal:
            AWS: "arn:aws:iam::123456789012:root"
          Action:
            - "sqs:SendMessage"
            - "sqs:ReceiveMessage"
          Resource: "arn:aws:sqs:us-east-1:123456789012:my-queue"
```

## Compliant Code Examples
```yaml
- name: First SQS queue with policy
  community.aws.sqs_queue:
    name: my-queue1
    region: ap-southeast-1
    default_visibility_timeout: 120
    message_retention_period: 86400
    maximum_message_size: 1024
    delivery_delay: 30
    receive_message_wait_time: 20
    policy:
      Version: '2012-10-17'
      Statement:
      - Effect: Allow
        Action: sqs:*
        Resource: '*'
        Principal: Principal
    make_default: false
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: First SQS queue with policy
  community.aws.sqs_queue:
    name: my-queue1
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
        Action: "*"
        Resource: "*"
        Principal:
          AWS: "*"
    make_default: false
    state: present

```