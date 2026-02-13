---
title: "Unrestricted SQL server access"
group_id: "Terraform / Azure"
meta:
  name: "azure/unrestricted_sql_server_access"
  id: "d7ba74da-2da0-4d4b-83c8-2fd72a3f6c28"
  display_name: "Unrestricted SQL server access"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `d7ba74da-2da0-4d4b-83c8-2fd72a3f6c28`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Critical

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/3.6.0/docs/resources/sql_firewall_rule)

### Description

This vulnerability occurs when Azure SQL Server firewall rules allow access from a wide range of IP addresses or use the `0.0.0.0` address, potentially exposing the database to unauthorized access from the internet. Overly permissive firewall rules significantly increase the attack surface and risk of data breaches or unauthorized access to sensitive database information. To secure your SQL Server, define tight IP ranges in your firewall rules, as shown in the secure example below:

```terraform
resource "azurerm_sql_firewall_rule" "secure_example" {
  name                = "FirewallRule1"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_sql_server.example.name
  start_ip_address    = "10.0.17.62"
  end_ip_address      = "10.0.17.62"
}
```

Avoid wide IP ranges or using `0.0.0.0` as seen in insecure configurations.

## Compliant Code Examples
```terraform
resource "azurerm_resource_group" "negative1" {
  name     = "acceptanceTestResourceGroup1"
  location = "West US"
}

resource "azurerm_sql_server" "negative2" {
  name                         = "mysqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = "West US"
  version                      = "12.0"
  administrator_login          = "4dm1n157r470r"
  administrator_login_password = "4-v3ry-53cr37-p455w0rd"
}

resource "azurerm_sql_firewall_rule" "negative3" {
  name                = "FirewallRule1"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_sql_server.example.name
  start_ip_address    = "10.0.17.62"
  end_ip_address      = "10.0.17.62"
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_resource_group" "positive1" {
  name     = "acceptanceTestResourceGroup1"
  location = "West US"
}

resource "azurerm_sql_server" "positive2" {
  name                         = "mysqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = "West US"
  version                      = "12.0"
  administrator_login          = "4dm1n157r470r"
  administrator_login_password = "4-v3ry-53cr37-p455w0rd"
}

resource "azurerm_sql_firewall_rule" "positive3" {
  name                = "FirewallRule1"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_sql_server.example.name
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "10.0.27.62"
}

resource "azurerm_sql_firewall_rule" "positive4" {
  name                = "FirewallRule1"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_sql_server.example.name
  start_ip_address    = "10.0.17.62"
  end_ip_address      = "10.0.27.62"
}

```