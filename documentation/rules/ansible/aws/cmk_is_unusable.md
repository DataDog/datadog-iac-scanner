---
title: "CMK is unusable"
group_id: "Ansible / AWS"
meta:
  name: "aws/cmk_is_unusable"
  id: "133fee21-37ef-45df-a563-4d07edc169f4"
  display_name: "CMK is unusable"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Availability"
---
## Metadata

**Id:** `133fee21-37ef-45df-a563-4d07edc169f4`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Availability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/aws_kms_module.html#parameter-enabled)

### Description

KMS Customer Master Keys (CMKs) must be usable, as disabled or scheduled-for-deletion keys cannot decrypt data and may cause service outages or data inaccessibility.

In Ansible `community.aws.aws_kms` tasks, ensure `enabled` is defined and set to `true`, and that `pending_window` is not defined. Tasks with `enabled` set to `false` or with `enabled` undefined are flagged. Any task that sets `pending_window` (scheduling the key for deletion) is also flagged because it renders the key unusable after the pending window expires.

Secure example for Ansible:

```yaml
- name: create KMS key
  community.aws.aws_kms:
    name: my-key
    description: "Key for encrypting secrets"
    state: present
    enabled: true
```

## Compliant Code Examples
```yaml
- name: Update IAM policy on an existing KMS key
  community.aws.aws_kms:
    alias: my-kms-key
    policy: '{"Version": "2012-10-17", "Id": "my-kms-key-permissions", "Statement": [ { <SOME STATEMENT> } ]}'
    state: present
    enabled: true

```
## Non-Compliant Code Examples
```yaml
- name: Update IAM policy on an existing KMS key2
  community.aws.aws_kms:
    alias: my-kms-key
    policy: '{"Version": "2012-10-17", "Id": "my-kms-key-permissions", "Statement": [ { <SOME STATEMENT> } ]}'
    state: present
    pending_window: 8

```

```yaml
- name: Update IAM policy on an existing KMS key1
  community.aws.aws_kms:
    alias: my-kms-key
    policy: '{"Version": "2012-10-17", "Id": "my-kms-key-permissions", "Statement": [ { <SOME STATEMENT> } ]}'
    state: present
    enabled: false

```