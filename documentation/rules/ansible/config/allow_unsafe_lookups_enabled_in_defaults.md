---
title: "Allow unsafe lookups enabled in defaults"
group_id: "Ansible / Ansible Config"
meta:
  name: "config/allow_unsafe_lookups_enabled_in_defaults"
  id: "ansible-allow-unsafe-lookups-enabled-in-defaults"
  display_name: "Allow unsafe lookups enabled in defaults"
  cloud_provider: "Ansible Config"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-allow-unsafe-lookups-enabled-in-defaults{{< /copyable-code >}}

**Cloud Provider:** Ansible Config

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#default-allow-unsafe-lookups)

### Description

The Ansible `allow_unsafe_lookups` option must be disabled. When enabled, lookup plugins can return values that bypass safety markers, which can expose sensitive data or cause playbooks to process untrusted input. Check the `defaults.allow_unsafe_lookups` property in your Ansible configuration and ensure it is defined and set to `False`. Configurations with this property set to `True` are flagged. Set this option in your `ansible.cfg` under the `[defaults]` section as shown in the following example:

```ini
[defaults]
allow_unsafe_lookups = False
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
fact_caching_prefix=ansible_facts
fact_caching_timeout=86400
collections_on_ansible_version_mismatch=warning
collections_path=~/.ansible/collections:/usr/share/ansible/collections
collections_scan_sys_path=True
command_warnings=False
action_plugins=~/.ansible/plugins/action:/usr/share/ansible/plugins/action

allow_unsafe_lookups=False
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
become_plugins=~/.ansible/plugins/become:/usr/share/ansible/plugins/become
fact_caching=memory
fact_caching_prefix=ansible_facts
fact_caching_timeout=86400
collections_on_ansible_version_mismatch=warning
collections_path=~/.ansible/collections:/usr/share/ansible/collections
collections_scan_sys_path=True
command_warnings=False
action_plugins=~/.ansible/plugins/action:/usr/share/ansible/plugins/action
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
become_plugins=~/.ansible/plugins/become:/usr/share/ansible/plugins/become
fact_caching=memory
fact_caching_prefix=ansible_facts
fact_caching_timeout=86400
collections_on_ansible_version_mismatch=warning
collections_path=~/.ansible/collections:/usr/share/ansible/collections
collections_scan_sys_path=True
command_warnings=False
action_plugins=~/.ansible/plugins/action:/usr/share/ansible/plugins/action

allow_unsafe_lookups=True
```