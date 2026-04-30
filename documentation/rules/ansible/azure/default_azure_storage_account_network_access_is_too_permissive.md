---
title: "Default Azure storage account network access is too permissive"
group_id: "Ansible / Azure"
meta:
  name: "azure/default_azure_storage_account_network_access_is_too_permissive"
  id: "ansible-azure-default-azure-storage-account-network-access-is-too-permissive"
  display_name: "Default Azure storage account network access is too permissive"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `ansible-azure-default-azure-storage-account-network-access-is-too-permissive`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_storageaccount_module.html#parameter-public_network_access)

### Description

Storage accounts must not permit broad public access or use a permissive default ACL. Public network access or a default-allow policy can expose blobs, queues, and file storage to unauthorized users, increasing the risk of data exfiltration.

For Ansible resources using `azure.azcollection.azure_rm_storageaccount` or `azure_rm_storageaccount`, explicitly set `public_network_access` to `Disabled` and set `network_acls.default_action` to `Deny`. Resources that omit `public_network_access` (the default is `Enabled`), that set `public_network_access: Enabled`, or that set `network_acls.default_action: Allow` are flagged.

Secure configuration example:

```yaml
- name: Create secure Azure Storage Account
  azure_rm_storageaccount:
    resource_group: my-rg
    name: mystorageacct
    location: eastus
    public_network_access: Disabled
    network_acls:
      default_action: Deny
```

## Compliant Code Examples
```yaml
---
- name: create an account
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    tags:
      testing: testing
      delete: on-exit
    network_acls:
      default_action: Deny

```

```yaml
---
- name: create an account
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    tags:
      testing: testing
      delete: on-exit
    public_network_access: Disabled

```
## Non-Compliant Code Examples
```yaml
---
- name: create an account
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    tags:
      testing: testing
      delete: on-exit

```

```yaml
---
- name: create an account
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    tags:
      testing: testing
      delete: on-exit
    network_acls:
      default_action: Allow

```

```yaml
---
- name: create an account
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    tags:
      testing: testing
      delete: on-exit
    public_network_access: Enabled

```