---
title: "Privilege Escalation Using Become Plugin In Defaults"
group_id: "Ansible / Ansible Config"
meta:
  name: "config/privilege_escalation_using_become_plugin_in_defaults"
  id: "404908b6-4954-4611-98f0-e8ceacdabcb1"
  display_name: "Privilege Escalation Using Become Plugin In Defaults"
  cloud_provider: "Ansible Config"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `404908b6-4954-4611-98f0-e8ceacdabcb1`

**Cloud Provider:** Ansible Config

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/plugins/become.html)

### Description

Specifying a `become_user` without enabling privilege escalation prevents Ansible from elevating privileges, so tasks intended to run as that user will execute as the invoking user, which can cause configuration changes to be applied with incorrect permissions or fail to run and lead to insecure or inconsistent system state. In the Ansible defaults group, when `defaults.become_user` is defined the `defaults.become` property must be present and set to `true`. This rule flags defaults entries where `become_user` exists but `become` is missing or set to `false`.

Secure configuration example:

```yaml
defaults:
  become: true
  become_user: root
```

## Compliant Code Examples
```ini
[defaults]
action_warnings=True
cowsay_enabled_stencils=bud-frogs, bunny, cheese, daemon, default, dragon, elephant-in-snake, elephant, eyes, hellokitty, kitty, luke-koala, meow, milk, moofasa, moose, ren, sheep, small, stegosaurus, stimpy, supermilker, three-eyes, turkey, turtle, tux, udder, vader-koala, vader, www
cow_selection=default
force_color=False
nocolor=False
nocows=False
any_errors_fatal=False
become_plugins=~/.ansible/plugins/become:/usr/share/ansible/plugins/become
fact_caching=memory
```

```ini
[defaults]
action_warnings=True
cowsay_enabled_stencils=bud-frogs, bunny, cheese, daemon, default, dragon, elephant-in-snake, elephant, eyes, hellokitty, kitty, luke-koala, meow, milk, moofasa, moose, ren, sheep, small, stegosaurus, stimpy, supermilker, three-eyes, turkey, turtle, tux, udder, vader-koala, vader, www
cow_selection=default
force_color=False
nocolor=False
nocows=False
any_errors_fatal=False
fact_caching=memory
become_ask_pass=False
become_method=sudo
become=True
become_user=root
```
## Non-Compliant Code Examples
```ini
[defaults]
action_warnings=True
cowsay_enabled_stencils=bud-frogs, bunny, cheese, daemon, default, dragon, elephant-in-snake, elephant, eyes, hellokitty, kitty, luke-koala, meow, milk, moofasa, moose, ren, sheep, small, stegosaurus, stimpy, supermilker, three-eyes, turkey, turtle, tux, udder, vader-koala, vader, www
cow_selection=default
force_color=False
nocolor=False
nocows=False
any_errors_fatal=False
fact_caching=memory
become_ask_pass=False
become_method=sudo
become_user=root
```

```ini
[defaults]
action_warnings=True
cowsay_enabled_stencils=bud-frogs, bunny, cheese, daemon, default, dragon, elephant-in-snake, elephant, eyes, hellokitty, kitty, luke-koala, meow, milk, moofasa, moose, ren, sheep, small, stegosaurus, stimpy, supermilker, three-eyes, turkey, turtle, tux, udder, vader-koala, vader, www
cow_selection=default
force_color=False
nocolor=False
nocows=False
any_errors_fatal=False
fact_caching=memory
become=False
become_ask_pass=False
become_method=sudo
become_user=root
```