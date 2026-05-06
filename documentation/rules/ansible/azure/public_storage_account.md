---
title: "Public storage account"
group_id: "Ansible / Azure"
meta:
  name: "azure/public_storage_account"
  id: "35e2f133-a395-40de-a79d-b260d973d1bd"
  display_name: "Public storage account"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** {{</* copyable-code */>}}35e2f133-a395-40de-a79d-b260d973d1bd{{</* copyable-code */>}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_storageaccount_module.html#parameter-network_acls)

### Description

Storage accounts must not allow public network access. Broad network access or open IP ranges expose account endpoints and data to unauthorized access and exfiltration.

For Ansible `azure_rm_storageaccount` and `azure.azcollection.azure_rm_storageaccount` tasks, ensure `network_acls.default_action` is not set to `"Allow"` (use `"Deny"`). When `default_action` is `"Deny"`, the `network_acls.ip_rules` list must not contain the catch-all `"0.0.0.0/0"`. Resources missing these properties, with `default_action='Allow'`, or with `ip_rules` containing `0.0.0.0/0` are flagged. 

Secure example for an Ansible task:

```yaml
- name: Create storage account with restricted network access
  azure.azcollection.azure_rm_storageaccount:
    resource_group: my-rg
    name: mystorageacct
    location: eastus
    network_acls:
      default_action: Deny
      ip_rules:
        - value: 203.0.113.5/32
```

## Compliant Code Examples
```yaml
- name: configure firewall and virtual networks
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    network_acls:
      bypass: AzureServices,Metrics
      default_action: Deny
      ip_rules:
      - value: 1.2.3.4
        action: Allow

```
## Non-Compliant Code Examples
```yaml
- name: configure firewall and virtual networks
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0002
    type: Standard_RAGRS
    network_acls:
      bypass: AzureServices,Metrics
      default_action: Deny
      ip_rules:
        - value: 0.0.0.0/0
          action: Allow
- name: configure firewall and more virtual networks
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0003
    type: Standard_RAGRS
    network_acls:
      bypass: AzureServices,Metrics
      default_action: Allow

```