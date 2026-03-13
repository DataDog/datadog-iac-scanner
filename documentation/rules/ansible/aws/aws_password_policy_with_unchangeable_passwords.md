---
title: "AWS password policy with unchangeable passwords"
group_id: "Ansible / AWS"
meta:
  name: "aws/aws_password_policy_with_unchangeable_passwords"
  id: "e28ceb92-d588-4166-aac5-766c8f5b7472"
  display_name: "AWS password policy with unchangeable passwords"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `e28ceb92-d588-4166-aac5-766c8f5b7472`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/iam_password_policy_module.html)

### Description

IAM password policies must permit users to change their own passwords so compromised, expired, or weak credentials can be rotated and account recovery workflows remain effective. In Ansible tasks using the `community.aws.iam_password_policy` or `iam_password_policy` modules, the boolean property controlling this must be defined and set to `true` — either `allow_pw_change` or `allow_password_change` depending on module version.

Tasks that omit these properties or set them to `false`/`no` are flagged because disabling password changes prevents credential rotation and hampers incident response and account hygiene.

Secure Ansible example:

```yaml
- name: Ensure IAM password policy allows user password changes
  community.aws.iam_password_policy:
    allow_password_change: true
```

## Compliant Code Examples
```yaml
- name: Password policy for AWS account
  community.aws.iam_password_policy:
    state: present
    min_pw_length: 8
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: true
    pw_max_age: 60
    pw_reuse_prevent: 5
    pw_expire: false

```
## Non-Compliant Code Examples
```yaml
- name: Password policy for AWS account
  community.aws.iam_password_policy:
    state: present
    min_pw_length: 8
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: false
    pw_max_age: 60
    pw_reuse_prevent: 5
    pw_expire: false
- name: Alias Password policy for AWS account
  community.aws.iam_password_policy:
    state: present
    min_pw_length: 8
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_password_change: false
    pw_max_age: 60
    pw_reuse_prevent: 5
    pw_expire: false

```