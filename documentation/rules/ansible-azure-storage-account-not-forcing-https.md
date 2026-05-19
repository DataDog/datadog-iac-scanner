---
title: "Storage account not forcing HTTPS"
group_id: "Ansible / Azure"
meta:
  name: ""azure/storage_account_not_forcing_https""
  id: "ansible-azure-storage-account-not-forcing-https"
  display_name: "Storage account not forcing HTTPS"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-azure-storage-account-not-forcing-https{{< /copyable-code >}}

**Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_storageaccount_module.html#parameter-https_only)

### Description

Storage Accounts must enforce HTTPS-only connections to prevent sensitive data from being transmitted in cleartext and reduce the risk of man-in-the-middle interception. For Ansible tasks using `azure.azcollection.azure_rm_storageaccount` or `azure_rm_storageaccount`, the `https_only` property must be set to `true`. Resources where `https_only` is missing (it defaults to `false`) or explicitly set to `false` are flagged. 

Secure example:

```yaml
- name: Create storage account with HTTPS enforced
  azure.azcollection.azure_rm_storageaccount:
    name: myStorageAccount
    resource_group: myResourceGroup
    location: eastus
    account_type: Standard_LRS
    https_only: true
```

## Compliant Code Examples
```yaml
- name: create an account
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: yes
    tags:
      testing: testing
      delete: on-exit
- name: create an account2
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: true
    tags:
      testing: testing
      delete: on-exit
- name: create an account3
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: true
    tags:
      testing: testing
      delete: on-exit
- name: create an account4
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: 'true'
    tags:
      testing: testing
      delete: on-exit
- name: create an account5
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: 'True'
    tags:
      testing: testing
      delete: on-exit
- name: create an account6
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: yes
    tags:
      testing: testing
      delete: on-exit
- name: create an account7
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: Yes
    tags:
      testing: testing
      delete: on-exit
- name: create an account8
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: Yes
    tags:
      testing: testing
      delete: on-exit

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
- name: create an account2
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: false
    tags:
      testing: testing
      delete: on-exit
- name: create an account3
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: False
    tags:
      testing: testing
      delete: on-exit
- name: create an account4
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: no
    tags:
      testing: testing
      delete: on-exit
- name: create an account5
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: No
    tags:
      testing: testing
      delete: on-exit
- name: create an account6
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: "false"
    tags:
      testing: testing
      delete: on-exit
- name: create an account7
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: "False"
    tags:
      testing: testing
      delete: on-exit
- name: create an account8
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: "no"
    tags:
      testing: testing
      delete: on-exit
- name: create an account9
  azure.azcollection.azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    https_only: "No"
    tags:
      testing: testing
      delete: on-exit

```