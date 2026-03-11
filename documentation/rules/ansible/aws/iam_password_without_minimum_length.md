---
title: "IAM Password Without Minimum Length"
group_id: "Ansible / AWS"
meta:
  name: "aws/iam_password_without_minimum_length"
  id: "8bc2168c-1723-4eeb-a6f3-a1ba614b9a6d"
  display_name: "IAM Password Without Minimum Length"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `8bc2168c-1723-4eeb-a6f3-a1ba614b9a6d`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/iam_password_policy_module.html)

### Description

IAM password policies must enforce a minimum length to reduce the risk of credential brute-force and credential-stuffing attacks and to limit the effectiveness of weak passwords. This rule checks Ansible tasks using `community.aws.iam_password_policy` or `iam_password_policy` and requires the `min_pw_length` or `minimum_password_length` property to be set to a numeric value of at least 8. Tasks missing both properties will be flagged as MissingAttribute, and tasks where the configured value is less than 8 will be flagged as IncorrectValue. Configure the property to 8 or higher; for example, a secure Ansible task:

```yaml
- name: Enforce IAM password policy
  community.aws.iam_password_policy:
    min_pw_length: 12
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

- name: aws_iam_account_password_policy
  community.aws.iam_password_policy:
    state: present
    minimum_password_length: 8
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
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: true
    pw_max_age: 60
    pw_reuse_prevent: 5
    pw_expire: false

- name: aws_iam_account_password_policy
  community.aws.iam_password_policy:
    state: present
    min_pw_length: 3
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: true
    pw_max_age: 60
    pw_reuse_prevent: 5
    pw_expire: false

- name: aws_iam_account_password_policy_2
  community.aws.iam_password_policy:
    state: present
    minimum_password_length: 3
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: true
    pw_max_age: 60
    pw_reuse_prevent: 5
    pw_expire: false

```