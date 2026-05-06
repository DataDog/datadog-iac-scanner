---
title: "VM not attached to network"
group_id: "Ansible / Azure"
meta:
  name: "azure/vm_not_attached_to_network"
  id: "1e5f5307-3e01-438d-8da6-985307ed25ce"
  display_name: "VM not attached to network"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{</* copyable-code */>}}1e5f5307-3e01-438d-8da6-985307ed25ce{{</* copyable-code */>}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_virtualmachine_module.html#parameter-network_interface_names)

### Description

Virtual machines should reference explicit network interfaces so network security controls (for example, Network Security Groups) can be applied and network exposure is predictable. Without explicit NIC configuration, instances may be created without NSGs or with default networking that exposes them to unintended access.

For Ansible VM tasks using `azure.azcollection.azure_rm_virtualmachine` or `azure_rm_virtualmachine`, either the `network_interface_names` property (a list of existing NIC names) or the `network_interfaces` property (a list of interface definitions) must be defined. Tasks missing both `network_interface_names` and `network_interfaces` are flagged. This rule verifies the presence of NIC references only and does not validate whether the referenced NICs themselves have NSGs attached.

Secure configuration examples:

```yaml
- name: Create VM with NIC name
  azure.azcollection.azure_rm_virtualmachine:
    name: myVM
    resource_group: myRG
    network_interface_names:
      - myNic

- name: Create VM with inline NIC definition
  azure.azcollection.azure_rm_virtualmachine:
    name: myVM2
    resource_group: myRG
    network_interfaces:
      - name: myNic2
        primary: true
```

## Compliant Code Examples
```yaml
- name: Create a VM with a custom image
  azure_rm_virtualmachine:
    resource_group: myResourceGroup
    name: testvm001
    vm_size: Standard_DS1_v2
    admin_username: adminUser
    admin_password: password01
    image: customimage001
    network_interfaces: testvm001

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

```