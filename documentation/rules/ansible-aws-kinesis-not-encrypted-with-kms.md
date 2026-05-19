---
title: "Kinesis not encrypted with KMS"
group_id: "Ansible / AWS"
meta:
  name: ""aws/kinesis_not_encrypted_with_kms""
  id: "ansible-aws-kinesis-not-encrypted-with-kms"
  display_name: "Kinesis not encrypted with KMS"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-kinesis-not-encrypted-with-kms{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/kinesis_stream_module.html)

### Description

Kinesis Data Streams must have server-side encryption enabled to protect stream data and metadata at rest and reduce the risk of unauthorized access or data exposure.

For Ansible resources using the `community.aws.kinesis_stream` or `kinesis_stream` module, the `encryption_state` property must be set to `"enabled"` and the `encryption_type` property must be defined and not set to `"NONE"`. If `encryption_type` is `"KMS"`, a valid `key_id` (KMS key ARN or ID) must also be provided.

Resources missing these properties or with `encryption_state != "enabled"`, `encryption_type == "NONE"`, or `encryption_type == "KMS"` without `key_id` are flagged.

Secure Ansible configuration example:

```yaml
- name: Create Kinesis stream with SSE-KMS
  community.aws.kinesis_stream:
    name: my-stream
    shard_count: 1
    encryption_state: enabled
    encryption_type: KMS
    key_id: arn:aws:kms:us-east-1:123456789012:key/abcd1234-ef56-7890-abcd-ef1234567890
```

## Compliant Code Examples
```yaml
- name: Encrypt Kinesis Stream test-stream. v6
  community.aws.kinesis_stream:
    name: test-stream
    state: present
    shards: 1
    encryption_state: enabled
    encryption_type: KMS
    key_id: alias/aws/kinesis
    wait: yes
    wait_timeout: 600

```
## Non-Compliant Code Examples
```yaml
- name: Encrypt Kinesis Stream test-stream.
  community.aws.kinesis_stream:
    name: test-stream
    state: present
    shards: 1
    encryption_type: KMS
    key_id: alias/aws/kinesis
    wait: yes
    wait_timeout: 600
  register: test_stream
- name: Encrypt Kinesis Stream test-stream. v2
  community.aws.kinesis_stream:
    name: test-stream
    state: present
    shards: 1
    encryption_state: disabled
    encryption_type: KMS
    key_id: alias/aws/kinesis
    wait: yes
    wait_timeout: 600
  register: test_stream
- name: Encrypt Kinesis Stream test-stream. v3
  community.aws.kinesis_stream:
    name: test-stream
    state: present
    shards: 1
    encryption_state: enabled
    key_id: alias/aws/kinesis
    wait: yes
    wait_timeout: 600
  register: test_stream
- name: Encrypt Kinesis Stream test-stream. v4
  community.aws.kinesis_stream:
    name: test-stream
    state: present
    shards: 1
    encryption_state: enabled
    encryption_type: NONE
    key_id: alias/aws/kinesis
    wait: yes
    wait_timeout: 600
  register: test_stream
- name: Encrypt Kinesis Stream test-stream. v5
  community.aws.kinesis_stream:
    name: test-stream
    state: present
    shards: 1
    encryption_state: enabled
    encryption_type: KMS
    wait: yes
    wait_timeout: 600
  register: test_stream

```