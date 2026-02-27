---
title: "Sqlserver ingress from any IP"
group_id: "Terraform / Azure"
meta:
  name: "azure/sql_server_ingress_from_any_ip"
  id: "25c0ea09-f1c5-4380-b055-3b83863f2bb8"
  display_name: "Sqlserver ingress from any IP"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `25c0ea09-f1c5-4380-b055-3b83863f2bb8`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Critical

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/3.6.0/docs/resources/sql_firewall_rule)

### Description

This check identifies Azure SQL Server firewall rules that allow access from any IP address (`0.0.0.0` to `255.255.255.255`), creating a significant security vulnerability by exposing your database to the entire internet. Such unrestricted access increases the risk of unauthorized access, data breaches, and potential exfiltration of sensitive information stored in your SQL databases.

Instead of allowing all IPs, you should configure specific IP ranges or addresses that require access. For example, use specific IP addresses such as `start_ip_address = "10.0.17.62"` and `end_ip_address = "10.0.17.62"`, instead of the insecure configuration with `start_ip_address = "0.0.0.0"` and `end_ip_address = "255.255.255.255"`.

## Compliant Code Examples
```terraform
resource "azurerm_sql_firewall_rule" "negative1" {
  name                = "FirewallRule1"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_sql_server.example.name
  start_ip_address    = "10.0.17.62"
  end_ip_address      = "10.0.17.62"
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_sql_firewall_rule" "positive1" {
  name                = "FirewallRule1"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_sql_server.example.name
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "255.255.255.255"
}
```