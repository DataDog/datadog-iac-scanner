---
title: "Azure Cognitive Search public network access enabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/azure_cognitive_search_public_network_access_enabled"
  id: "4a9e0f00-0765-4f72-a0d4-d31110b78279"
  display_name: "Azure Cognitive Search public network access enabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `4a9e0f00-0765-4f72-a0d4-d31110b78279`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/search_service#public_network_access_enabled)

### Description

Allowing public network access to Azure Cognitive Search exposes the service to the internet, increasing the risk of unauthorized access and data exposure. In Terraform, this is controlled by the `public_network_access_enabled` attribute; setting this attribute to `true` permits public connections, while setting it to `false` restricts access to trusted, private networks only. For example, a secure configuration would look like the following:

```
resource "azurerm_search_service" "example" {
  name                          = "example-search-service"
  resource_group_name           = azurerm_resource_group.example.name
  location                      = azurerm_resource_group.example.location
  sku                           = "standard"
  public_network_access_enabled = false
}
```

Leaving public access enabled may allow attackers to enumerate, access, or exfiltrate sensitive search indexes and data.

## Compliant Code Examples
```terraform
resource "azurerm_search_service" "example" {
  name                = "example-search-service"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"
  public_network_access_enabled = false
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_search_service" "positive2" {
  name                = "example-search-service"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"
}

```

```terraform
resource "azurerm_search_service" "positive1" {
  name                = "example-search-service"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"
  public_network_access_enabled = true
}

```