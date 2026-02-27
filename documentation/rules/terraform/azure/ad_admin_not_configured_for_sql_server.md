---
title: "AD admin not configured for SQL server"
group_id: "Terraform / Azure"
meta:
  name: "azure/ad_admin_not_configured_for_sql_server"
  id: "a3a055d2-9a2e-4cc9-b9fb-12850a1a3a4b"
  display_name: "AD admin not configured for SQL server"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `a3a055d2-9a2e-4cc9-b9fb-12850a1a3a4b`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/3.6.0/docs/resources/sql_active_directory_administrator)

### Description

When a SQL server in Azure is not configured with an Active Directory (AD) administrator, access control is limited to SQL authentication accounts, which lack the centralized identity management and advanced security features provided by Azure AD. This can make the SQL server more difficult to manage securely and can increase the risk of unauthorized access if user accounts are not handled properly. Enabling AD authentication by specifying an `azurerm_sql_active_directory_administrator` resource ensures that access can be centrally managed and monitored, helping enforce organizational security policies. 

A secure Terraform configuration example should look like the following:
```
resource "azurerm_sql_active_directory_administrator" "example" {
  server_name         = "mysqlserver"
  resource_group_name = "acceptanceTestResourceGroup1"
  login               = "sqladmin"
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = data.azurerm_client_config.current.object_id
}
```

## Compliant Code Examples
```terraform
resource "azurerm_resource_group" "negative1" {
  name     = "acceptanceTestResourceGroup1"
  location = "West US"
}

resource "azurerm_sql_server" "negative2" {
  name                         = "mysqlserver"
  resource_group_name          = "acceptanceTestResourceGroup1"
  location                     = "West US"
  version                      = "12.0"
  administrator_login          = "4dm1n157r470r"
  administrator_login_password = "4-v3ry-53cr37-p455w0rd"
}

resource "azurerm_sql_active_directory_administrator" "negative3" {
  server_name         = "mysqlserver"
  resource_group_name = "acceptanceTestResourceGroup1"
  login               = "sqladmin"
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = data.azurerm_client_config.current.object_id
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_resource_group" "positive1" {
  name     = "acceptanceTestResourceGroup1"
  location = "West US"
}

resource "azurerm_sql_server" "positive2" {
  name                         = "mysqlserver1"
  resource_group_name          = "acceptanceTestResourceGroup1"
  location                     = "West US"
  version                      = "12.0"
  administrator_login          = "4dm1n157r470r"
  administrator_login_password = "4-v3ry-53cr37-p455w0rd"
}

resource "azurerm_sql_active_directory_administrator" "positive3" {
  server_name         = "mysqlserver2"
  resource_group_name = "acceptanceTestResourceGroup1"
  login               = "sqladmin"
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = data.azurerm_client_config.current.object_id
}

```