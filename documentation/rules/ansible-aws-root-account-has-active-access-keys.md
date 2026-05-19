---
title: "Root account has active access keys"
group_id: "Ansible / AWS"
meta:
  name: ""aws/root_account_has_active_access_keys""
  id: "ansible-aws-root-account-has-active-access-keys"
  display_name: "Root account has active access keys"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-root-account-has-active-access-keys{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/iam_access_key_module.html)

### Description

Active root access keys grant full, account-wide privileges. A leaked key could lead to immediate and complete compromise of the environment. This rule inspects Ansible tasks using the `amazon.aws.iam_access_key` or `iam_access_key` modules and flags entries where `user_name` contains "root", the `active` property is `true` (or absent, since `true` is the default), and `state` is not `absent`.

The `active` property must not be `true` for root account entries. Resources should either omit root access keys or set `active` to `false`. Any task with an active root access key is flagged. Remove or deactivate root access keys and use IAM users or roles with least privilege for automation and service access.

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: Create root access key but inactive
  amazon.aws.iam_access_key:
    user_name: root
    active: false

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: Create root access key
  amazon.aws.iam_access_key:
    user_name: root
    state: present

```