---
title: "IAM Access Key Is Exposed"
group_id: "Ansible / AWS"
meta:
  name: "aws/iam_access_key_is_exposed"
  id: "7f79f858-fbe8-4186-8a2c-dfd0d958a40f"
  display_name: "IAM Access Key Is Exposed"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `7f79f858-fbe8-4186-8a2c-dfd0d958a40f`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/iam_module.html)

### Description

Active, long‑lived access keys for non‑root IAM users increase the risk of credential compromise and unauthorized API access because leaked keys can be used to impersonate users and perform privileged actions. This rule inspects Ansible tasks that use the `community.aws.iam` or `iam` modules and flags tasks where the `access_key_state` property is set to `active` while the `name` property does not contain `root`. Resources with `access_key_state='active'` for non‑root users will be flagged; remediate by removing or setting unused keys to `inactive`, rotating keys frequently, or replacing long‑lived keys with IAM roles and temporary credentials. The check is case‑insensitive and treats any username containing the substring `root` as the root account exception.

## Compliant Code Examples
```yaml
# Basic user creation example
- name: Create two new IAM users with API keys
  community.aws.iam:
    iam_type: user
    name: '{{ item }}'
    state: present
    password: '{{ temp_pass }}'
    access_key_state: create
  loop:
  - jcleese
  - mpython

# Basic user creation example
- name: Create two new IAM users with API keys
  community.aws.iam:
    iam_type: user
    name: root
    state: present
    password: '{{ temp_pass }}'
    access_key_state: active

- name: Create Two Groups, Mario and Luigi
  community.aws.iam:
    iam_type: group
    name: '{{ item }}'
    state: present
  loop:
  - Mario
  - Luigi
  register: new_groups

- name: Update user
  community.aws.iam:
    iam_type: user
    name: jdavila
    state: update
    access_key_state: inactive
    groups: '{{ item.created_group.group_name }}'
  loop: '{{ new_groups.results }}'

```
## Non-Compliant Code Examples
```yaml
- name: Create two new IAM users with API keys
  community.aws.iam:
    iam_type: user
    name: "{{ item }}"
    state: present
    password: "{{ temp_pass }}"
    access_key_state: active
  loop:
    - jcleese
    - mpython
- name: Create two new IAM users with API keys
  community.aws.iam:
    iam_type: user
    name: "{{ item }}"
    state: present
    password: "{{ temp_pass }}"
    access_key_state: active
  loop:
    - root
    - mpython
- name: Create Two Groups, Mario and Luigi
  community.aws.iam:
    iam_type: group
    name: "{{ item }}"
    state: present
    access_key_state: active
  loop:
    - Mario
    - Luigi
  register: new_groups
- name: Update user
  community.aws.iam:
    iam_type: user
    name: jdavila
    state: update
    access_key_state: active
    groups: "{{ item.created_group.group_name }}"
  loop: "{{ new_groups.results }}"

```