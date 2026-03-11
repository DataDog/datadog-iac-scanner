---
title: "Storage Account Not Using Latest TLS Encryption Version"
group_id: "Ansible / Azure"
meta:
  name: "azure/storage_account_not_using_latest_tls_encryption_version"
  id: "c62746cf-92d5-4649-9acf-7d48d086f2ee"
  display_name: "Storage Account Not Using Latest TLS Encryption Version"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `c62746cf-92d5-4649-9acf-7d48d086f2ee`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_storageaccount_module.html#parameter-minimum_tls_version)

### Description

Storage accounts must enforce TLS 1.2 to protect data in transit and to prevent use of older, vulnerable TLS versions or downgrade attacks. For Ansible, the `azure_rm_storageaccount` or `azure.azcollection.azure_rm_storageaccount` resource must include the `minimum_tls_version` property set to `"TLS1_2"`. Resources missing `minimum_tls_version` or configured with any value other than `"TLS1_2"` (for example `"TLS1_0"` or `"TLS1_1"`) will be flagged.

## Compliant Code Examples
```yaml
- name: Create an account with kind of FileStorage
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: c1h0002
    type: Premium_LRS
    kind: FileStorage
    minimum_tls_version: TLS1_2
    tags:
      testing: testing

```
## Non-Compliant Code Examples
```yaml
---
- name: Create an account with kind of FileStorage
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: c1h0002
    type: Premium_LRS
    kind: FileStorage
    minimum_tls_version: TLS1_0
    tags:
      testing: testing
- name: Create a second account with kind of FileStorage
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0003
    type: Premium_LRS
    kind: FileStorage

```