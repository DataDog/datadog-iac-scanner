---
title: "Cosmos DB account without tags"
group_id: "Terraform / Azure"
meta:
  name: "azure/cosmos_db_account_without_tags"
  id: "56dad03e-e94f-4dd6-93a4-c253a03ff7a0"
  display_name: "Cosmos DB account without tags"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `56dad03e-e94f-4dd6-93a4-c253a03ff7a0`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cosmosdb_account)

### Description

 Cosmos DB accounts should be configured with appropriate tags to ensure resources are identifiable, manageable, and auditable within an Azure environment. Without tags, as shown below, critical contextual information—such as environment, owner, or cost center—is missing, making resource management and cost tracking difficult:

```
resource "azurerm_cosmosdb_account" "example" {
  // ...other configuration...
}
```

By specifying the `tags` attribute, as demonstrated here, organizations can better enforce governance, automate resource management, and control costs:

```
resource "azurerm_cosmosdb_account" "example" {
  // ...other configuration...
  tags = {
    Environment = "Production"
    Owner       = "AppTeam"
  }
}
```

Leaving tags unconfigured can lead to unmanaged resources, increased risk of misconfiguration, and operational inefficiencies.


## Compliant Code Examples
```terraform
resource "azurerm_cosmosdb_account" "negative1" {
  name                = "tfex-cosmos-db-${random_integer.ri.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"
  tags                = "tag_1"
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_cosmosdb_account" "positive1" {
  name                = "tfex-cosmos-db-${random_integer.ri.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"
}
```