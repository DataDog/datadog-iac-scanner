---
title: "Trusted Microsoft Services Not Enabled"
group_id: "Ansible / Azure"
meta:
  name: "azure/trusted_microsoft_services_not_enabled"
  id: "1bc398a8-d274-47de-a4c8-6ac867b353de"
  display_name: "Trusted Microsoft Services Not Enabled"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `1bc398a8-d274-47de-a4c8-6ac867b353de`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_storageaccount_module.html#parameter-network_acls/bypass)

### Description

When a Storage Account's network access is restricted (network_acls.default_action = Deny), Trusted Microsoft Services must be allowed to bypass the network rules so platform features such as Azure Backup, diagnostics/monitoring, and replication can access the account; without this, backups, telemetry, and other managed operations can fail, impacting data protection and operational visibility. In Ansible `azure_rm_storageaccount` or `azure.azcollection.azure_rm_storageaccount` resources, ensure the `network_acls.bypass` property includes the value `AzureServices` (it may be a comma-separated list, e.g., `AzureServices,Logging`) whenever `network_acls.default_action` is `Deny`. Resources that omit `network_acls.bypass` or whose `bypass` value does not contain `AzureServices` will be flagged.

Secure configuration example:

```yaml
- name: Create storage account with AzureServices bypass
  azure_rm_storageaccount:
    resource_group: my-rg
    name: mystorageacct
    location: eastus
    account_type: Standard_LRS
    network_acls:
      default_action: Deny
      bypass: AzureServices
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
      virtual_network_rules:
      - id: /subscriptions/mySubscriptionId/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVnet/subnets/mySubnet
        action: Allow
      ip_rules:
      - value: 1.2.3.4
        action: Allow
      - value: 123.234.123.0/24
        action: Allow
- name: configure firewall and virtual networks2
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0003
    type: Standard_RAGRS
    network_acls:
      default_action: Deny
      virtual_network_rules:
      - id: /subscriptions/mySubscriptionId/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVnet/subnets/mySubnet
        action: Allow
      ip_rules:
      - value: 1.2.3.4
        action: Allow
      - value: 123.234.123.0/24
        action: Allow
- name: configure firewall and virtual networks3
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0004
    type: Standard_RAGRS
    network_acls:
      default_action: Deny
      bypass: AzureServices
      virtual_network_rules:
      - id: /subscriptions/mySubscriptionId/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVnet/subnets/mySubnet
        action: Allow
      ip_rules:
      - value: 1.2.3.4
        action: Allow
      - value: 123.234.123.0/24
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
      bypass: Metrics
      default_action: Deny
      virtual_network_rules:
        - id: /subscriptions/mySubscriptionId/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVnet/subnets/mySubnet
          action: Allow
      ip_rules:
        - value: 1.2.3.4
          action: Allow
        - value: 123.234.123.0/24
          action: Allow
- name: configure firewall and virtual networks2
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0003
    type: Standard_RAGRS
    network_acls:
      default_action: Deny
      bypass: Metrics,Logging
      virtual_network_rules:
        - id: /subscriptions/mySubscriptionId/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVnet/subnets/mySubnet
          action: Allow
      ip_rules:
        - value: 1.2.3.4
          action: Allow
        - value: 123.234.123.0/24
          action: Allow
- name: configure firewall and virtual networks3
  azure_rm_storageaccount:
    resource_group: myResourceGroup
    name: clh0004
    type: Standard_RAGRS
    network_acls:
      default_action: Deny
      bypass: ""
      virtual_network_rules:
        - id: /subscriptions/mySubscriptionId/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVnet/subnets/mySubnet
          action: Allow
      ip_rules:
        - value: 1.2.3.4
          action: Allow
        - value: 123.234.123.0/24
          action: Allow

```