---
title: "Admin user enabled for container registry"
group_id: "Terraform / Azure"
meta:
  name: "azure/admin_user_enabled_for_container_registry"
  id: "b897dfbf-322c-45a8-b67c-1e698beeaa51"
  display_name: "Admin user enabled for container registry"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `b897dfbf-322c-45a8-b67c-1e698beeaa51`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://www.terraform.io/docs/providers/azurerm/r/container_registry.html)

### Description

 Enabling the admin user for an Azure Container Registry by setting the `admin_enabled` attribute to `true` in Terraform exposes static credentials that can be used to access and manage the registry. This increases the attack surface, as the admin username and key are global for the registry and can be easily leaked or abused if compromised. To mitigate this risk, the admin user should be disabled by setting `admin_enabled = false`:

```
resource "azurerm_container_registry" "example" {
  // other arguments
  admin_enabled = false
}
```


## Compliant Code Examples
```terraform
resource "azurerm_resource_group" "negative1" {
  name     = "resourceGroup1"
  location = "West US"
}

resource "azurerm_container_registry" "negative2" {
  name                     = "containerRegistry1"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  sku                      = "Premium"
  admin_enabled            = false
  georeplication_locations = ["East US", "West Europe"]
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_resource_group" "positive1" {
  name     = "resourceGroup1"
  location = "West US"
}

resource "azurerm_container_registry" "positive2" {
  name                     = "containerRegistry1"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  sku                      = "Premium"
  admin_enabled            = true
  georeplication_locations = ["East US", "West Europe"]
}
```