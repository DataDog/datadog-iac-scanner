---
title: "IAM access key is exposed"
group_id: "Ansible / AWS"
meta:
  name: "aws/iam_access_key_is_exposed"
  id: "7f79f858-fbe8-4186-8a2c-dfd0d958a40f"
  display_name: "IAM access key is exposed"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** {{</* copyable-code */>}}7f79f858-fbe8-4186-8a2c-dfd0d958a40f{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/iam_access_key_module.html)

### Description

Active, long‑lived access keys for non‑root IAM users increase the risk of credential compromise and unauthorized API access because leaked keys can be used to impersonate users and perform privileged actions. This rule inspects Ansible tasks that use the `amazon.aws.iam_access_key` or `iam_access_key` modules and flags tasks where the `active` property is `true` (or absent, since `true` is the default) and the `state` is not `absent`, while the `user_name` property does not contain `root`.

Resources with active access keys for non‑root users are flagged. Remediate by removing or deactivating unused keys, rotating keys frequently, or replacing long‑lived keys with IAM roles and temporary credentials. The check is case‑insensitive and treats any username containing the substring `root` as the root account exception.

## Compliant Code Examples
```yaml
# Root user with active key (covered by root_account_has_active_access_keys)
- name: Create root access key
  amazon.aws.iam_access_key:
    user_name: root
    state: present

# Non-root user with inactive key
- name: Create inactive access key
  amazon.aws.iam_access_key:
    user_name: jcleese
    active: false

# Non-root user with absent state
- name: Remove access key
  amazon.aws.iam_access_key:
    user_name: jdavila
    state: absent

```
## Non-Compliant Code Examples
```yaml
- name: Create non-root user with active access key
  amazon.aws.iam_access_key:
    user_name: jcleese
    state: present
- name: Create another non-root user with active access key
  amazon.aws.iam_access_key:
    user_name: mpython
    state: present

```