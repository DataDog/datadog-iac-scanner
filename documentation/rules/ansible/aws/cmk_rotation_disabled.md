---
title: "CMK rotation disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/cmk_rotation_disabled"
  id: "af96d737-0818-4162-8c41-40d969bd65d1"
  display_name: "CMK rotation disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** {{</* copyable-code */>}}af96d737-0818-4162-8c41-40d969bd65d1{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/kms_key_module.html#parameter-enable_key_rotation)

### Description

Customer Master Keys (CMKs) must have automatic key rotation enabled to limit how long a compromised key can be used and to meet key lifecycle and compliance requirements.

In Ansible, for tasks using the `amazon.aws.kms_key` module, when `enabled: true` and the key is not scheduled for deletion (no `pending_window` defined), the `enable_key_rotation` property must be present and set to `true`. Resources missing `enable_key_rotation` or with `enable_key_rotation: false` are flagged as misconfigured.

Secure configuration example:

```
- name: Create CMK with rotation enabled
  amazon.aws.kms_key:
    name: my-key
    enabled: true
    enable_key_rotation: true
```

## Compliant Code Examples
```yaml
- name: Update IAM policy on an existing KMS key3
  amazon.aws.kms_key:
    alias: my-kms-key
    policy: '{"Version": "2012-10-17", "Id": "my-kms-key-permissions", "Statement": [ { <SOME STATEMENT> } ]}'
    state: present
    enabled: true
    enable_key_rotation: true

```
## Non-Compliant Code Examples
```yaml
- name: Update IAM policy on an existing KMS key2
  amazon.aws.kms_key:
    alias: my-kms-key
    policy: '{"Version": "2012-10-17", "Id": "my-kms-key-permissions", "Statement": [ { <SOME STATEMENT> } ]}'
    state: present
    enabled: true
    enable_key_rotation: false

```

```yaml
- name: Update IAM policy on an existing KMS key
  amazon.aws.kms_key:
    alias: my-kms-key
    policy: '{"Version": "2012-10-17", "Id": "my-kms-key-permissions", "Statement": [ { <SOME STATEMENT> } ]}'
    state: present
    enabled: true

```