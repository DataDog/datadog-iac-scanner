---
title: "SQS queue with SSE disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/sqs_with_sse_disabled"
  id: "ansible-aws-sqs-queue-with-sse-disabled"
  display_name: "SQS queue with SSE disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `ansible-aws-sqs-queue-with-sse-disabled`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/sqs_queue_module.html#ansible-collections-community-aws-sqs-queue-module)

### Description

SQS queues must have server-side encryption (SSE) enabled to protect message contents at rest and in backups. This reduces the risk of exposing sensitive data if someone accesses the underlying storage or compromises credentials.

In Ansible, tasks using the `community.aws.sqs_queue` or `sqs_queue` modules must define the `kms_master_key_id` property and set it to a valid KMS key identifier (for example, a KMS ARN, key ID, or alias) to enable KMS-backed SSE. Resources missing this property or with it undefined/empty are flagged. Using a customer-managed KMS key (ARN or key ID) is recommended for granular access control and auditability, though the AWS-managed alias (`alias/aws/sqs`) can be used if customer-managed keys are not required.

Secure configuration example:

```yaml
- name: Create encrypted SQS queue
  community.aws.sqs_queue:
    name: my-queue
    kms_master_key_id: arn:aws:kms:us-east-1:123456789012:key/abcd1234-56ef-78gh-90ij-klmnopqrstuv
```

## Compliant Code Examples
```yaml
- name: Configure Encryption, automatically uses a new data key every hour
  community.aws.sqs_queue:
    name: fifo-queue
    region: ap-southeast-2
    kms_master_key_id: alias/MyQueueKey
    kms_data_key_reuse_period_seconds: 3600

- name: Delete SQS queue
  community.aws.sqs_queue:
    name: my-queue
    region: ap-southeast-2
    state: absent

```
## Non-Compliant Code Examples
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
    policy: "{{ json_dict }}"
    redrive_policy:
      maxReceiveCount: 5
      deadLetterTargetArn: arn:aws:sqs:eu-west-1:123456789012:my-dead-queue

- name: Drop redrive policy
  community.aws.sqs_queue:
    name: my-queue
    region: ap-southeast-2
    redrive_policy: {}

- name: Create FIFO queue
  community.aws.sqs_queue:
    name: fifo-queue
    region: ap-southeast-2
    queue_type: fifo
    content_based_deduplication: yes

- name: Tag queue
  community.aws.sqs_queue:
    name: fifo-queue
    region: ap-southeast-2
    tags:
      example: SomeValue

```