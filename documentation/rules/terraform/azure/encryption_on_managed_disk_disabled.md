---
title: "Encryption on managed disk disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/encryption_on_managed_disk_disabled"
  id: "a99130ab-4c0e-43aa-97f8-78d4fcb30024"
  display_name: "Encryption on managed disk disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `a99130ab-4c0e-43aa-97f8-78d4fcb30024`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk#encryption_settings)

### Description

 When creating Azure managed disks with Terraform, it is important to ensure that encryption is enabled to protect data at rest. If the `encryption_settings` block either has `enabled = false` or is omitted entirely, as shown below, the disk's contents are left unencrypted and may be exposed if the disk is compromised or accessed by unauthorized users.:

```
resource "azurerm_managed_disk" "example" {
  // ... other parameters ...
  encryption_settings = {
    enabled = false
  }
}
```

Enabling encryption with `encryption_settings = { enabled = true }` ensures sensitive data is protected from unauthorized access and helps meet compliance requirements.


## Compliant Code Examples
```terraform

resource "azurerm_managed_disk" "negative1" {
  name                 = "acctestmd"
  location             = "West US 2"
  resource_group_name  = azurerm_resource_group.example.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = "1"
  
  encryption_settings = {
      enabled = true
  }
  tags = {
    environment = "staging"
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_managed_disk" "positive1" {
  name                 = "acctestmd"
  location             = "West US 2"
  resource_group_name  = azurerm_resource_group.example.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = "1"

  encryption_settings = {
      enabled = false
  }

  tags = {
    environment = "staging"
  }
}

resource "azurerm_managed_disk" "positive2" {
  name                 = "acctestmd"
  location             = "West US 2"
  resource_group_name  = azurerm_resource_group.example.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = "1"
  

  tags = {
    environment = "staging"
  }
}
```