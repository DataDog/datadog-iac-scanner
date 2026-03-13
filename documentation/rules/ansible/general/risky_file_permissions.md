---
title: "Risky file permissions"
group_id: "Ansible / Common"
meta:
  name: "general/risky_file_permissions"
  id: "88841d5c-d22d-4b7e-a6a0-89ca50e44b9f"
  display_name: "Risky file permissions"
  cloud_provider: "Common"
  platform: "Ansible"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** `88841d5c-d22d-4b7e-a6a0-89ca50e44b9f`

**Cloud Provider:** Common

**Platform:** Ansible

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://ansible.readthedocs.io/projects/lint/rules/risky-file-permissions/)

### Description

Files and directories created or modified by Ansible tasks must have explicit, least-privilege file modes. Omitting the `mode` or relying on preserved/default permissions can leave artifacts world-readable or writable, increasing the risk of data exposure and privilege escalation.

This rule checks file-related modules—`archive`, `assemble`, `copy`, `file`, `get_url`, `template` (including their FQCNs) and content-creation modules like `htpasswd` and `ini_file`. Tasks that create files (task `state` not `absent`/`link`) without defining the `mode` property are flagged.

For modules that provide a `create` boolean (for example `htpasswd` and `ini_file`), tasks where `create` is true (or defaults to true) and `mode` is not defined are also flagged. `mode: preserve` is only allowed for `copy` and `template` modules. Any other module using `mode: preserve` is reported as invalid.

To remediate, add an explicit `mode` with an appropriate octal value, or set `create: false` when creation is not desired.

```yaml
- name: Create config file with restrictive permissions
  ansible.builtin.file:
    path: /etc/myapp/config.yml
    state: file
    mode: '0640'

- name: Create ini file with explicit mode
  community.general.ini_file:
    path: /etc/myapp/settings.ini
    create: true
    mode: '0640'
```

## Compliant Code Examples
```yaml
---
- name: SUCCESS_PERMISSIONS_PRESENT
  hosts: all
  tasks:
    - name: Permissions not missing and numeric
      ansible.builtin.file:
        path: foo
        mode: "0600"

---
- name: SUCCESS_PERMISSIONS_PRESENT_GET_URL
  hosts: all
  tasks:
    - name: Permissions not missing and numeric
      ansible.builtin.get_url:
        url: http://foo
        dest: foo
        mode: "0600"

---
- name: SUCCESS_ABSENT_STATE
  hosts: all
  tasks:
    - name: Permissions missing while state is absent is fine
      ansible.builtin.file:
        path: foo
        state: absent

---
- name: SUCCESS_DEFAULT_STATE
  hosts: all
  tasks:
    - name: Permissions missing while state is file (default) is fine
      ansible.builtin.file:
        path: foo

---
- name: SUCCESS_LINK_STATE
  hosts: all
  tasks:
    - name: Permissions missing while state is link is fine
      ansible.builtin.file:
        path: foo2
        src: foo
        state: link

---
- name: SUCCESS_CREATE_FALSE
  hosts: all
  tasks:
    - name: File edit when create is false
      ansible.builtin.lineinfile:
        path: foo
        create: false
        line: some content here

---
- name: SUCCESS_REPLACE
  hosts: all
  tasks:
    - name: Replace should not require mode
      ansible.builtin.replace:
        path: foo
        regexp: foo

---
- name: SUCCESS_RECURSE
  hosts: all
  tasks:
    - name: File with recursive does not require mode
      ansible.builtin.file:
        state: directory
        recurse: true
        path: foo
    - name: Permissions not missing and numeric (fqcn)
      ansible.builtin.file:
        path: bar
        mode: "755"
    - name: File edit when create is false (fqcn)
      ansible.builtin.lineinfile:
        path: foo
        create: false
        line: some content here

---
- name: LINIINFILE_CREATE
  tasks: 
    - name: create is true 2x
      lineinfile:
        path: foo
        line: some content here
        mode: "0600"

---
- name: PRESERVE_MODE
  tasks:
    - name: not preserve value
      copy:
        path: foo
        mode: preserve

---
- name: LINEINFILE_CREATE2
  tasks:
    - name: create_false
      ansible.builtin.lineinfile:
        path: foo
        create: true
        line: some content here
        mode: "644"

```
## Non-Compliant Code Examples
```yaml
---
- name: PRESERVE_MODE
  tasks:
    - name: not preserve value
      ansible.builtin.file:
        path: foo
        mode: preserve

---
- name: MISSING_PERMISSIONS_TOUCH
  tasks:
    - name: Permissions missing
      file:
        path: foo
        state: touch
    - name: Permissions missing 2x
      ansible.builtin.file:
        path: foo
        state: touch

---
- name: MISSING_PERMISSIONS_DIRECTORY
  tasks:
    - name: Permissions missing 3x
      file:
        path: foo
        state: directory
    - name: create is true
      ansible.builtin.lineinfile:
        path: foo
        create: true
        line: some content here

---
- name: MISSING_PERMISSIONS_GET_URL
  tasks:
    - name: Permissions missing 4x
      get_url:
        url: http://foo
        dest: foo

---
- name: LINEINFILE_CREATE
  tasks:
    - name: create is true 2x
      ansible.builtin.lineinfile:
        path: foo
        create: true
        line: some content here

---
- name: REPLACE_PRESERVE
  tasks:
    - name: not preserve mode 2x
      replace:
        path: foo
        mode: preserve
        regexp: foo

---
- name: NOT_PERMISSION
  tasks:
    - name: Not Permissions
      file:
        path: foo
        owner: root
        group: root
        state: directory

---
- name: LINEINFILE_CREATE2
  tasks:
    - name: create_false
      ansible.builtin.lineinfile:
        path: foo
        create: true
        line: some content here
        mode: preserve
```