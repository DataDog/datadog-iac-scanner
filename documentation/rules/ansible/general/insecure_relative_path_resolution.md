---
title: "Insecure relative path resolution"
group_id: "Ansible / Common"
meta:
  name: "general/insecure_relative_path_resolution"
  id: "ansible-insecure-relative-path-resolution"
  display_name: "Insecure relative path resolution"
  cloud_provider: "Common"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `ansible-insecure-relative-path-resolution`

**Cloud Provider:** Common

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://ansible.readthedocs.io/projects/lint/rules/no-relative-paths/)

### Description

Using upward-relative src paths in Ansible copy or template tasks (for example, `../templates` or `../files`) can cause unpredictable file selection and accidental inclusion of sensitive files. The path is resolved against the current working directory, which may differ across control hosts or CI runs.

This rule examines tasks that use the modules `copy`, `win_copy`, `template`, `win_template`, `ansible.builtin.copy`, and `ansible.builtin.template`. Any task whose `src` property contains a `../<folder>` segment referencing role folders (for example, `../files`, `../templates`, `../win_templates`) is flagged.

Fix by placing assets in the role's `files`/`templates` directories and referencing them by name, or use absolute paths or `{{ role_path }}` when necessary so `src` does not include upward-traversal segments.

Secure examples:

```yaml
- name: Deploy config file
  copy:
    src: myapp.conf
    dest: /etc/myapp/myapp.conf

- name: Deploy template
  template:
    src: myapp.conf.j2
    dest: /etc/myapp/config.conf
```

## Compliant Code Examples
```yaml
---
- name: Negative Example
  hosts: localhost
  tasks:
    - name: One
      ansible.builtin.copy:
        content:
        dest: /etc/mine.conf
        mode: "0644"
    - name: Two
      ansible.builtin.copy:
        src: /home/example/files/foo.conf
        dest: /etc/foo.conf
        mode: "0644"

---
- name: Negative Example 2
  hosts: localhost
  tasks:
    - name: One
      ansible.builtin.template:
        src: ../example/foo.j2
        dest: /etc/file.conf
        mode: "0644"
    - name: Two
      ansible.builtin.copy:
        src: ../example/foo.conf
        dest: /etc/foo.conf
        mode: "0644"
    - name: Three
      win_template:
        src: ../example/foo2.j2
        dest: /etc/file.conf
        mode: "0644"
```
## Non-Compliant Code Examples
```yaml
---
- name: Positive Example
  hosts: localhost
  tasks:
    - name: One
      ansible.builtin.template:
        src: ../templates/foo.j2
        dest: /etc/file.conf
        mode: "0644"
    - name: Two
      ansible.builtin.copy:
        src: ../files/foo.conf
        dest: /etc/foo.conf
        mode: "0644"
```