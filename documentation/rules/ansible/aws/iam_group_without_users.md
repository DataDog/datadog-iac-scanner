---
title: "IAM group without users"
group_id: "Ansible / AWS"
meta:
  name: "aws/iam_group_without_users"
  id: "ansible-aws-iam-group-without-users"
  display_name: "IAM group without users"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-iam-group-without-users{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/iam_group_module.html)

### Description

IAM groups should include at least one user to ensure group membership and any attached permissions are intentional, auditable, and not left orphaned.

This rule checks Ansible `amazon.aws.iam_group` and `iam_group` tasks and requires the `users` property to be defined and non-null (a list containing one or more usernames). Resources missing the `users` property or with `users: null` or an empty list are flagged. Either populate the list with the intended usernames or remove unused groups and associated policies.

Secure configuration example:

```
- name: Create developers IAM group with users
  amazon.aws.iam_group:
    name: developers
    users:
      - alice
      - bob
    state: present
```

## Compliant Code Examples
```yaml
- name: Group3
  iam_group:
    name: testgroup2
    managed_policy:
      - arn:aws:iam::aws:policy/AmazonSNSFullAccess
    users:
      - test_user1
      - test_user2
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: Group2
  iam_group:
    name: testgroup2
    managed_policy:
      - arn:aws:iam::aws:policy/AmazonSNSFullAccess
    users:
    state: present

```

```yaml
- name: Group1
  iam_group:
    name: testgroup1
    state: present

```