---
title: "Logging of Sensitive Data"
group_id: "Ansible / Common"
meta:
  name: "general/logging_of_sensitive_data"
  id: "59029ddf-e651-412b-ae7b-ff6d403184bc"
  display_name: "Logging of Sensitive Data"
  cloud_provider: "Common"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `59029ddf-e651-412b-ae7b-ff6d403184bc`

**Cloud Provider:** Common

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://ansible.readthedocs.io/projects/lint/rules/no-log-password/)

### Description

Tasks that create or modify users and set a `password` can emit plaintext credentials in playbook output and logs, risking credential leakage and unauthorized access. For `ansible.builtin.user` tasks that include the `password` property, the task-level `no_log` attribute must be defined and set to `true`. Tasks missing `no_log` or with `no_log: false` will be flagged by this rule. Apply `no_log: true` to any task that handles plaintext secrets or templated variables that resolve to secrets.

```yaml
- name: Create application user without exposing password
  ansible.builtin.user:
    name: appuser
    password: "{{ appuser_password }}"
  no_log: true
```

## Compliant Code Examples
```yaml
---
- name: Negative playbook
  hosts: localhost
  tasks:
    - name: foo
      ansible.builtin.user:
        name: john_doe
        comment: John Doe
        uid: 1040
        group: admin
        password: "{{ item }}"
      with_items:
        - wow
      no_log: true
  
---
- name: Negative Playbook 2
  hosts: localhost
  tasks:
    - name: bar
      ansible.builtin.user:
        name: john_doe
        comment: John Doe
        uid: 1040
        group: admin
      with_items:
        - wow
      no_log: false

---
- name: Negative Playbook 3
  hosts: localhost
  tasks:
    - name: bar
      ansible.builtin.user:
        name: john_doe
        comment: John Doe
        uid: 1040
        group: admin
      with_items:
        - wow
```
## Non-Compliant Code Examples
```yaml
---
- name: Positive Playbook
  hosts: localhost
  tasks:
    - name: bar
      ansible.builtin.user:
        name: john_doe
        comment: John Doe
        uid: 1040
        group: admin
        password: "{{ item }}"
      with_items:
        - wow
```

```yaml
---
- name: Positive Playbook
  hosts: localhost
  tasks:
    - name: bar
      ansible.builtin.user:
        name: john_doe
        comment: John Doe
        uid: 1040
        group: admin
        password: "{{ item }}"
      with_items:
        - wow
      no_log: false
```