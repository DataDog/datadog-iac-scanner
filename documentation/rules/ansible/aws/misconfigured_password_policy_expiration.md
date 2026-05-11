---
title: "Misconfigured password policy expiration"
group_id: "Ansible / AWS"
meta:
  name: "aws/misconfigured_password_policy_expiration"
  id: "ansible-aws-misconfigured-password-policy-expiration"
  display_name: "Misconfigured password policy expiration"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `ansible-aws-misconfigured-password-policy-expiration`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/iam_password_policy_module.html)

### Description

IAM account password policies must enforce regular password expiration to limit exposure from compromised or leaked credentials and reduce the risk of long-lived unauthorized access. In Ansible, tasks using the `amazon.aws.iam_password_policy` or `iam_password_policy` modules must define `pw_max_age` or `password_max_age` with a value of 90 days or fewer. Resources that omit both properties or set either to a value greater than 90 are flagged.

Secure configuration example:

```yaml
- name: Enforce IAM password expiration
  amazon.aws.iam_password_policy:
    password_max_age: 90
```

## Compliant Code Examples
```yaml
- name: Missing Password policy for AWS account
  amazon.aws.iam_password_policy:
    state: present
    min_pw_length: 8
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: true
    pw_max_age: 20
    pw_reuse_prevent: 5
    pw_expire: false

```
## Non-Compliant Code Examples
```yaml
- name: Missing Password policy for AWS account
  amazon.aws.iam_password_policy:
    state: present
    min_pw_length: 8
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: true
    pw_reuse_prevent: 5
    pw_expire: false
- name: Extreme Password policy for AWS account
  amazon.aws.iam_password_policy:
    state: present
    min_pw_length: 8
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: true
    pw_max_age: 180
    pw_reuse_prevent: 5
    pw_expire: false
- name: Alias extreme Password policy for AWS account
  amazon.aws.iam_password_policy:
    state: present
    min_pw_length: 8
    require_symbols: false
    require_numbers: true
    require_uppercase: true
    require_lowercase: true
    allow_pw_change: true
    password_max_age: 95
    pw_reuse_prevent: 5
    pw_expire: false

```