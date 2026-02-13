---
title: "Default Azure storage account network access is too permissive"
group_id: "Terraform / Azure"
meta:
  name: "azure/default_azure_storage_account_network_access_is_too_permissive"
  id: "a5613650-32ec-4975-a305-31af783153ea"
  display_name: "Default Azure storage account network access is too permissive"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `a5613650-32ec-4975-a305-31af783153ea`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#default_action)

### Description

Azure storage accounts should have their default network access action set to `Deny` to prevent unauthorized or public access to storage resources. If the `network_rules { default_action = "Allow" }` attribute is used, as shown below, storage accounts can be accessed from any network by default, increasing the risk of data breaches or unauthorized data manipulation.

```
network_rules {
  default_action = "Allow"
}
```

To mitigate this risk, configure `network_rules { default_action = "Deny" }`, ensuring only explicitly allowed networks and IPs can access the storage account.

## Compliant Code Examples
```terraform
resource "azurerm_resource_group" "example" {
  name     = "negative2-resources"
  location = "West Europe"
}

resource "azurerm_virtual_network" "negative2" {
  name                = "negative2-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_subnet" "negative2" {
  name                 = "negative2-subnet"
  resource_group_name  = azurerm_resource_group.example.name
  virtual_network_name = azurerm_virtual_network.negative2.name
  address_prefixes     = ["10.0.2.0/24"]
  service_endpoints    = ["Microsoft.Storage"]
}

resource "azurerm_storage_account" "negative2" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  tags = {
    environment = "staging"
  }
}

resource "azurerm_storage_account_network_rules" "negative2" {
  resource_group_name  = azurerm_resource_group.example.name
  storage_account_name = azurerm_storage_account.negative2.name
  storage_account_id = azurerm_storage_account.negative2.id

  default_action             = "Deny"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.negative2.id]
  bypass                     = ["Metrics"]
}

resource "azurerm_storage_account_network_rules" "negative2b" {
  resource_group_name  = azurerm_resource_group.example.name
  storage_account_name = azurerm_storage_account.negative3.name
  storage_account_id = azurerm_storage_account.negative3.id

  default_action             = "Deny"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.negative2.id]
  bypass                     = ["Metrics"]
}

```

```terraform
resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_virtual_network" "negative1" {
  name                = "virtnetname"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_subnet" "negative1" {
  name                 = "subnetname"
  resource_group_name  = azurerm_resource_group.example.name
  virtual_network_name = azurerm_virtual_network.negative1.name
  address_prefixes     = ["10.0.2.0/24"]
  service_endpoints    = ["Microsoft.Sql", "Microsoft.Storage"]
}

resource "azurerm_storage_account" "negative1" {
  name                = "storageaccountname"
  resource_group_name = azurerm_resource_group.example.name

  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action             = "Deny"
    ip_rules                   = ["100.0.0.1"]
    virtual_network_subnet_ids = [azurerm_subnet.negative1.id]
  }

  tags = {
    environment = "staging"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_resource_group" "example" {
  name     = "positive2-resources"
  location = "West Europe"
}

resource "azurerm_virtual_network" "positive2" {
  name                = "positive2-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_subnet" "positive2" {
  name                 = "positive2-subnet"
  resource_group_name  = azurerm_resource_group.example.name
  virtual_network_name = azurerm_virtual_network.positive2.name
  address_prefixes     = ["10.0.2.0/24"]
  service_endpoints    = ["Microsoft.Storage"]
}

resource "azurerm_storage_account" "positive2" {
  name                     = "positive2storageaccount"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  tags = {
    environment = "staging"
  }
}

resource "azurerm_storage_account_network_rules" "positive2" {
  resource_group_name  = azurerm_resource_group.example.name
  storage_account_name = azurerm_storage_account.positive2.name
  storage_account_id = azurerm_storage_account.positive2.id

  default_action             = "Allow"
  ip_rules                   = ["127.0.0.1"]
  virtual_network_subnet_ids = [azurerm_subnet.positive2.id]
  bypass                     = ["Metrics"]
}

```

```terraform
resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_storage_account" "positive3" {
  name                     = "positive3storageaccount"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  public_network_access_enabled = true

  tags = {
    environment = "staging"
  }
}
```

```terraform
resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_storage_account" "positive4" {
  name                     = "positive4storageaccount"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  tags = {
    environment = "staging"
  }
}
```