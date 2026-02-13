---
title: "Storage account not forcing HTTPS"
group_id: "Terraform / Azure"
meta:
  name: "azure/storage_account_not_forcing_https"
  id: "12944ec4-1fa0-47be-8b17-42a034f937c2"
  display_name: "Storage account not forcing HTTPS"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `12944ec4-1fa0-47be-8b17-42a034f937c2`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#https_traffic_only_enabled-1)

### Description

Storage accounts should enforce the use of HTTPS by setting the `https_traffic_only_enabled` attribute to `true` in the Terraform configuration. Allowing HTTP traffic (`https_traffic_only_enabled = false`) exposes sensitive data to interception and man-in-the-middle attacks during transit. A secure configuration should look like the following:

```
resource "azurerm_storage_account" "secure_example" {
  // ... other configuration ...
  https_traffic_only_enabled = true
}
```

Enforcing HTTPS ensures all connections to the storage account are encrypted, protecting data integrity and confidentiality.

## Compliant Code Examples
```terraform
resource "azurerm_storage_account" "positive2" {
  name                     = "example2"
  resource_group_name      = data.azurerm_resource_group.example.name
  location                 = data.azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  # will not flag because https_traffic_only_enabled is set to true by default so we do not error
}

```

```terraform
resource "azurerm_storage_account" "negative1" {
  name                       = "example"
  resource_group_name        = data.azurerm_resource_group.example.name
  location                   = data.azurerm_resource_group.example.location
  account_tier               = "Standard"
  account_replication_type   = "GRS"
  https_traffic_only_enabled = true # Set to true as desired
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_storage_account" "positive1" {
  name                       = "example1"
  resource_group_name        = data.azurerm_resource_group.example.name
  location                   = data.azurerm_resource_group.example.location
  account_tier               = "Standard"
  account_replication_type   = "GRS"
  https_traffic_only_enabled = false
}

```