---
title: "Azure Container Registry with no locks"
group_id: "Terraform / Azure"
meta:
  name: "azure/azure_container_registry_with_no_locks"
  id: "a187ac47-8163-42ce-8a63-c115236be6fb"
  display_name: "Azure Container Registry with no locks"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `a187ac47-8163-42ce-8a63-c115236be6fb`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry)

### Description

 Azure Container Registry without proper management locks is vulnerable to accidental deletion or modification, which can lead to service disruptions, data loss, and potentially severe business impact. Management locks provide an additional layer of protection by preventing unauthorized or unintended changes to critical resources. To properly secure an Azure Container Registry, ensure the management lock's scope correctly references the container registry resource, as shown below:

```
resource "azurerm_container_registry" "acr" {
  name = "containerRegistry1"
  resource_group_name = azurerm_resource_group.rg.name
  location = azurerm_resource_group.rg.location
  sku = "Standard"
  admin_enabled = false
}

resource "azurerm_management_lock" "public-ip" {
  name = "resource-ip"
  scope = azurerm_container_registry.acr.id
  lock_level = "CanNotDelete"
  notes = "Locked because it's needed by a third-party"
}
```


## Compliant Code Examples
```terraform
resource "azurerm_container_registry" "acr" {
name = "containerRegistry1"
resource_group_name = azurerm_resource_group.rg.name
location = azurerm_resource_group.rg.location
sku = "Standard"
admin_enabled = false
}


resource "azurerm_management_lock" "public-ip" {
name = "resource-ip"
scope = azurerm_container_registry.acr.id
lock_level = "CanNotDelete"
notes = "Locked because it's needed by a third-party"
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_container_registry" "acr" {
name = "containerRegistry1"
resource_group_name = azurerm_resource_group.rg.name
location = azurerm_resource_group.rg.location
sku = "Standard"
admin_enabled = false
}


resource "azurerm_management_lock" "public-ip" {
name = "resource-ip"
scope = azurerm_container_registry.acr1.id
lock_level = "CanNotDelete"
notes = "Locked because it's needed by a third-party"
}


```