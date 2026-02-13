---
title: "SQL server predictable admin account name"
group_id: "Terraform / Azure"
meta:
  name: "azure/sql_server_predictable_admin_account_name"
  id: "2ab6de9a-0136-415c-be92-79d2e4fd750f"
  display_name: "SQL server predictable admin account name"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `2ab6de9a-0136-415c-be92-79d2e4fd750f`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server)

### Description

 Azure SQL Server administrator login names should not use common or predictable values like `admin` or `administrator`. Using predictable names for the `administrator_login` attribute, such as `administrator_login = "Admin"`, makes brute force or credential stuffing attacks easier for malicious actors, increasing the risk of unauthorized database access. To mitigate this, configure the login with an unpredictable name, as shown below:

```
administrator_login = "UnpredictableAdminLogin"
```


## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
resource "azurerm_resource_group" "negative1" {
  name     = "database-rg"
  location = "West US"
}

resource "azurerm_storage_account" "negative2" {
  name                     = "examplesa"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_sql_server" "negative3" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "UnpredictableAdminLogin"
  administrator_login_password = "thisIsDog11"

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 6
  }

  tags = {
    environment = "production"
  }
}
```
## Non-Compliant Code Examples
```terraform
#this is a problematic code where the query should report a result(s)
resource "azurerm_resource_group" "positive1" {
  name     = "database-rg"
  location = "West US"
}

resource "azurerm_storage_account" "positive2" {
  name                     = "examplesa"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_sql_server" "positive3" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = ""
  administrator_login_password = "thisIsDog11"

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 6
  }

  tags = {
    environment = "production"
  }
}

resource "azurerm_sql_server" "positive4" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "Admin"
  administrator_login_password = "thisIsDog11"

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 6
  }

  tags = {
    environment = "production"
  }
}

```