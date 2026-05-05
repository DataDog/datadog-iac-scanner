---
title: "Privilege escalation using become plugin"
group_id: "Ansible / Common"
meta:
  name: "general/privilege_escalation_using_become_plugin"
  id: "ansible-common-privilege-escalation-using-become-plugin"
  display_name: "Privilege escalation using become plugin"
  cloud_provider: "Common"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `ansible-common-privilege-escalation-using-become-plugin`

**Cloud Provider:** Common

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://ansible.readthedocs.io/projects/lint/rules/partial-become/#problematic-code)

### Description

Playbooks and tasks that specify a target user with `become_user` must also enable privilege escalation so actions execute with the intended elevated privileges. Without `become: true`, commands run as the unprivileged connection user or fail. This can lead to misconfiguration, failed security controls, or unintended access to sensitive resources. Verify the `become` property is defined and set to `true` on `ansible_playbook` and `ansible_task` resources whenever `become_user` is present. Resources where `become_user` is defined but `become` is missing or `false` are flagged for correction.

Secure examples:

```yaml
- hosts: servers
  become: true
  become_user: root
  tasks:
    - name: Perform privileged action
      command: /usr/bin/some-command
```

```yaml
- name: Install package
  become: true
  become_user: root
  apt:
    name: nginx
    state: present
```

## Compliant Code Examples
```yaml
---
- hosts: localhost
  become_user: postgres
  become: true
  tasks:
    - name: some task
      ansible.builtin.command: whoamyou
      changed_when: false

---
- hosts: localhost
  tasks:
    - name: become from the same scope
      ansible.builtin.command: whoami
      become: true
      become_user: postgres
      changed_when: false
```
## Non-Compliant Code Examples
```yaml
---
- hosts: localhost
  name: become_user without become
  become_user: bar

  tasks:
    - name: Simple hello
      ansible.builtin.debug:
        msg: hello

---
- hosts: localhost
  name: become_user with become false
  become_user: root
  become: false

  tasks:
    - name: Simple hello
      ansible.builtin.debug:
        msg: hello

---
- hosts: localhost
  tasks:
    - name: become and become_user on different tasks
      block:
        - name: Sample become
          become: true
          ansible.builtin.command: ls .
        - name: Sample become_user
          become_user: foo
          ansible.builtin.command: ls .

---
- hosts: localhost
  tasks:
    - name: become false
      block:
        - name: Sample become
          become: true
          ansible.builtin.command: ls .
        - name: Sample become_user
          become_user: postgres
          become: false
          ansible.builtin.command: ls .

---
- hosts: localhost
  tasks:
    - name: become_user with become task as false
      ansible.builtin.command: whoami
      become_user: mongodb
      become: false
      changed_when: false

---
- hosts: localhost
  tasks:
    - name: become_user without become
      ansible.builtin.command: whoami
      become_user: mysql
      changed_when: false
```