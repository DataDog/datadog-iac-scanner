---
title: "Root Account Has Active Access Keys"
group_id: "Ansible / AWS"
meta:
  name: "aws/root_account_has_active_access_keys"
  id: "e71d0bc7-d9e8-4e6e-ae90-0a4206db6f40"
  display_name: "Root Account Has Active Access Keys"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `e71d0bc7-d9e8-4e6e-ae90-0a4206db6f40`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/iam_module.html)

### Description

The AWS root account must not have active access keys because active root credentials grant full, account-wide privileges and a leaked key would allow immediate and complete compromise of the environment. This rule inspects Ansible tasks using the `community.aws.iam` or `iam` modules and flags entries where `iam.iam_type == "user"` and `iam.name` contains "root" and the `access_key_state` property is set to `"active"`. The `access_key_state` property must not be `"active"` for root account entries; resources should either omit root access keys or have `access_key_state` set to `"inactive"`, and any task with `access_key_state="active"` will be flagged. Remove or deactivate root access keys and use IAM users or roles with least privilege for automation and service access instead of relying on root credentials.

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: Create two new IAM users with API keys
  community.aws.iam:
    iam_type: user
    name: '{{ root }}'
    state: present
    password: '{{ temp_pass }}'
    access_key_state: inactive
  loop:
  - jcleese
  - mpython

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: Create two new IAM users with API keys
  community.aws.iam:
    iam_type: user
    name: "{{ root }}"
    state: present
    password: "{{ temp_pass }}"
    access_key_state: active
  loop:
    - jcleese
    - mpython

```