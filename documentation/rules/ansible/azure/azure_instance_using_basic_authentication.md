---
title: "Azure instance using basic authentication"
group_id: "Ansible / Azure"
meta:
  name: "azure/azure_instance_using_basic_authentication"
  id: "e2d834b7-8b25-4935-af53-4a60668dcbe0"
  display_name: "Azure instance using basic authentication"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** {{</* copyable-code */>}}e2d834b7-8b25-4935-af53-4a60668dcbe0{{</* copyable-code */>}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_virtualmachine_module.html#parameter-linux_config/disable_password_authentication)

### Description

Linux virtual machines must require SSH key authentication instead of username/password. Password-based login is susceptible to brute-force attacks and credential compromise, which can lead to unauthorized access and lateral movement.

For Ansible `azure_rm_virtualmachine` resources, ensure `ssh_password_enabled` is set to `false` and `linux_config.disable_password_authentication` is set to `true` so only SSH key authentication is allowed. This rule applies to resources intended to be Linux VMs (where `os_type` is `"linux"` or unspecified). Resources missing these properties or that allow password authentication are flagged.

Secure example configuration:

```yaml
- name: Create Linux VM with SSH keys only
  azure_rm_virtualmachine:
    name: my-linux-vm
    resource_group: my-rg
    os_type: Linux
    ssh_password_enabled: false
    linux_config:
      disable_password_authentication: true
    ssh_public_keys:
      - path: /home/azureuser/.ssh/authorized_keys
        key_data: "{{ lookup('file','~/.ssh/id_rsa.pub') }}"
```

## Compliant Code Examples
```yaml
---
- name: Create a VM with a custom image
  azure_rm_virtualmachine:
    resource_group: myResourceGroup
    name: testvm001
    vm_size: Standard_DS1_v2
    ssh_password_enabled: false
    ssh_public_keys:
      - path: ~/.ssh/id_rsa.pub
        key_data: somegeneratedkeydata
    image: customimage001
    os_type: Linux

```
## Non-Compliant Code Examples
```yaml
---
- name: Create a VM with a custom image
  azure_rm_virtualmachine:
    resource_group: myResourceGroup
    name: testvm001
    vm_size: Standard_DS1_v2
    admin_username: adminUser
    admin_password: password01
    image: customimage001
    os_type: Linux

```