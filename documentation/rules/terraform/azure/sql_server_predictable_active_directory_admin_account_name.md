---
title: "SQL server predictable Active Directory admin account name"
group_id: "Terraform / Azure"
meta:
  name: "azure/sql_server_predictable_active_directory_admin_account_name"
  id: "bcd3fc01-5902-4f2a-b05a-227f9bbf5450"
  display_name: "SQL server predictable Active Directory admin account name"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `bcd3fc01-5902-4f2a-b05a-227f9bbf5450`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_active_directory_administrator)

### Description

Azure SQL Servers should not use predictable Active Directory Administrator account names, such as `Admin`, for the `login` attribute, as this increases the risk of brute-force or dictionary attacks. Using easily guessed usernames, such as `login = "Admin"`, increases the risk of unauthorized access by making accounts more susceptible to targeted attacks. To enhance security, use a unique and hard-to-guess login name, such as:

```
login = "NotEasyToPredictAdmin"
```
This helps reduce the likelihood of successful account compromise.

## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "negative1" {
  name     = "acceptanceTestResourceGroup1"
  location = "West US"
}

resource "azurerm_sql_server" "negative2" {
  name                         = "mysqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "4dm1n157r470r"
  administrator_login_password = "4-v3ry-53cr37-p455w0rd"
}

resource "azurerm_sql_active_directory_administrator" "negative3" {
  server_name         = azurerm_sql_server.example.name
  resource_group_name = azurerm_resource_group.example.name
  login               = "NotEasyToPredictAdmin"
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = data.azurerm_client_config.current.object_id
}
```
## Non-Compliant Code Examples
```terraform
#this is a problematic code where the query should report a result(s)
data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "positive1" {
  name     = "acceptanceTestResourceGroup1"
  location = "West US"
}

resource "azurerm_sql_server" "positive2" {
  name                         = "mysqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "4dm1n157r470r"
  administrator_login_password = "4-v3ry-53cr37-p455w0rd"
}

resource "azurerm_sql_active_directory_administrator" "positive3" {
  server_name         = azurerm_sql_server.example.name
  resource_group_name = azurerm_resource_group.example.name
  login               = ""
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = data.azurerm_client_config.current.object_id
}

resource "azurerm_sql_active_directory_administrator" "positive4" {
  server_name         = azurerm_sql_server.example.name
  resource_group_name = azurerm_resource_group.example.name
  login               = "Admin"
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = data.azurerm_client_config.current.object_id
}
```