---
title: "Logging of sensitive data in defaults"
group_id: "Ansible / Ansible Config"
meta:
  name: "config/logging_of_sensitive_data_in_defaults"
  id: "ansible-common-logging-of-sensitive-data-in-defaults"
  display_name: "Logging of sensitive data in defaults"
  cloud_provider: "Ansible Config"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `ansible-common-logging-of-sensitive-data-in-defaults`

**Cloud Provider:** Ansible Config

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/reference_appendices/logging.html#protecting-sensitive-data-with-no-log)

### Description

The Ansible `no_log` setting must be enabled to prevent sensitive data such as passwords, tokens, or PII from being written to logs. Exposed log data can be accessed by unauthorized users or retained in build artifacts. This rule applies to resources of type `ansible_config` in the `defaults` group. The `no_log` property must be defined and set to boolean `true`. Resources missing the `no_log` property or with `no_log` set to `false` are flagged as insecure. 

Secure configuration example for ansible.cfg:

```ini
[defaults]
no_log = True
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
ask_pass=False
ask_vault_pass=False
cache_plugins=~/.ansible/plugins/cache:/usr/share/ansible/plugins/cache
callback_plugins=~/.ansible/plugins/callback:/usr/share/ansible/plugins/callback
cliconf_plugins=~/.ansible/plugins/cliconf:/usr/share/ansible/plugins/cliconf
connection_plugins=~/.ansible/plugins/connection:/usr/share/ansible/plugins/connection
debug=False
executable=/bin/sh
filter_plugins=~/.ansible/plugins/filter:/usr/share/ansible/plugins/filter
force_handlers=False
forks=5
gathering=implicit
gather_subset=all
lookup_plugins=~/.ansible/plugins/lookup:/usr/share/ansible/plugins/lookup
ansible_managed=Ansible managed
module_compression=ZIP_DEFLATED
module_name=command
library=~/.ansible/plugins/modules:/usr/share/ansible/plugins/modules
module_utils=~/.ansible/plugins/module_utils:/usr/share/ansible/plugins/module_utils
netconf_plugins=~/.ansible/plugins/netconf:/usr/share/ansible/plugins/netconf
no_log=True
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
allow_unsafe_lookups=False
ask_pass=False
ask_vault_pass=False
cache_plugins=~/.ansible/plugins/cache:/usr/share/ansible/plugins/cache
callback_plugins=~/.ansible/plugins/callback:/usr/share/ansible/plugins/callback
cliconf_plugins=~/.ansible/plugins/cliconf:/usr/share/ansible/plugins/cliconf
connection_plugins=~/.ansible/plugins/connection:/usr/share/ansible/plugins/connection
debug=False
executable=/bin/sh
filter_plugins=~/.ansible/plugins/filter:/usr/share/ansible/plugins/filter
force_handlers=False
forks=5
gathering=implicit
gather_subset=all
lookup_plugins=~/.ansible/plugins/lookup:/usr/share/ansible/plugins/lookup
ansible_managed=Ansible managed
module_compression=ZIP_DEFLATED
module_name=command
library=~/.ansible/plugins/modules:/usr/share/ansible/plugins/modules
module_utils=~/.ansible/plugins/module_utils:/usr/share/ansible/plugins/module_utils
netconf_plugins=~/.ansible/plugins/netconf:/usr/share/ansible/plugins/netconf
no_log=False
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
allow_unsafe_lookups=False
ask_pass=False
ask_vault_pass=False
cache_plugins=~/.ansible/plugins/cache:/usr/share/ansible/plugins/cache
callback_plugins=~/.ansible/plugins/callback:/usr/share/ansible/plugins/callback
cliconf_plugins=~/.ansible/plugins/cliconf:/usr/share/ansible/plugins/cliconf
connection_plugins=~/.ansible/plugins/connection:/usr/share/ansible/plugins/connection
debug=False
executable=/bin/sh
filter_plugins=~/.ansible/plugins/filter:/usr/share/ansible/plugins/filter
force_handlers=False
forks=5
gathering=implicit
gather_subset=all
lookup_plugins=~/.ansible/plugins/lookup:/usr/share/ansible/plugins/lookup
ansible_managed=Ansible managed
module_compression=ZIP_DEFLATED
module_name=command
library=~/.ansible/plugins/modules:/usr/share/ansible/plugins/modules
module_utils=~/.ansible/plugins/module_utils:/usr/share/ansible/plugins/module_utils
netconf_plugins=~/.ansible/plugins/netconf:/usr/share/ansible/plugins/netconf
```