---
title: "Password without reuse prevention"
group_id: "Ansible / AWS"
meta:
  name: ""aws/password_without_reuse_prevention""
  id: "ansible-aws-password-without-reuse-prevention"
  display_name: "Password without reuse prevention"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-password-without-reuse-prevention{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/iam_password_policy_module.html#parameter-pw_reuse_prevent)

### Description

IAM password policies must prevent reuse of previous passwords to reduce the risk of account compromise from credential stuffing and replay of older credentials.

For Ansible tasks using the `amazon.aws.iam_password_policy` or `iam_password_policy` modules, define one of the reuse-prevention properties (`password_reuse_prevent`, `pw_reuse_prevent`, or `prevent_reuse`) and set it to a positive integer greater than 0. This specifies how many prior passwords are disallowed. This rule flags tasks where none of these properties are present or where the property is explicitly set to `0`.

Secure example (prevents reuse of the last 5 passwords):

```yaml
- name: Enforce IAM password reuse prevention
  amazon.aws.iam_password_policy:
    password_reuse_prevent: 5
```

## Compliant Code Examples
```yaml
- name: Password policy for AWS account
  amazon.aws.iam_password_policy:
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
- name: Password policy for AWS account2
  amazon.aws.iam_password_policy:
    state: present
    min_pw_length: 8
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: true
    pw_max_age: 60
    password_reuse_prevent: 5
    pw_expire: false
- name: Password policy for AWS account3
  amazon.aws.iam_password_policy:
    state: present
    min_pw_length: 8
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: true
    pw_max_age: 60
    prevent_reuse: 5
    pw_expire: false

```
## Non-Compliant Code Examples
```yaml
---
- name: Password policy for AWS account
  amazon.aws.iam_password_policy:
    state: present
    min_pw_length: 8
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: true
    pw_max_age: 60
    pw_expire: false
- name: Password policy for AWS account2
  amazon.aws.iam_password_policy:
    state: present
    min_pw_length: 8
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: true
    pw_max_age: 60
    password_reuse_prevent: 0
    pw_expire: false
- name: Password policy for AWS account3
  amazon.aws.iam_password_policy:
    state: present
    min_pw_length: 8
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: true
    pw_max_age: 60
    pw_expire: false

```