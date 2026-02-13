---
title: "SQL server alert email disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/sql_server_alert_email_disabled"
  id: "55975007-f6e7-4134-83c3-298f1fe4b519"
  display_name: "SQL server alert email disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `55975007-f6e7-4134-83c3-298f1fe4b519`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy#email_account_admins)

### Description

SQL Server alert emails should be enabled to ensure that administrators are promptly notified of suspicious activities or potential security threats, such as SQL injection or data exfiltration attempts. Without setting the `email_account_admins` attribute to `true` in the `azurerm_mssql_server_security_alert_policy` resource, critical security alerts may go unnoticed, delaying incident response and potentially increasing the risk of a successful attack. A secure configuration is shown below:

```
resource "azurerm_mssql_server_security_alert_policy" "example" {
  resource_group_name        = azurerm_resource_group.example.name
  server_name                = azurerm_sql_server.example.name
  state                      = "Enabled"
  storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  disabled_alerts = [
    "Sql_Injection",
    "Data_Exfiltration"
  ]
  retention_days = 20
  email_account_admins = true
}
```

Enabling alert emails reduces the risk of missing critical security events by ensuring they are communicated in real time to account administrators.

## Compliant Code Examples
```terraform
resource "azurerm_mssql_server_security_alert_policy" "negative" {
  resource_group_name        = azurerm_resource_group.example.name
  server_name                = azurerm_sql_server.example.name
  state                      = "Enabled"
  storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  disabled_alerts = [
    "Sql_Injection",
    "Data_Exfiltration"
  ]
  retention_days = 20
  email_account_admins = true
}


```
## Non-Compliant Code Examples
```terraform
resource "azurerm_mssql_server_security_alert_policy" "positive2" {
  resource_group_name        = azurerm_resource_group.example.name
  server_name                = azurerm_sql_server.example.name
  state                      = "Enabled"
  storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  disabled_alerts = [
    "Sql_Injection",
    "Data_Exfiltration"
  ]
  retention_days = 20
  email_account_admins = false
}

```

```terraform
resource "azurerm_mssql_server_security_alert_policy" "positive1" {
  resource_group_name        = azurerm_resource_group.example.name
  server_name                = azurerm_sql_server.example.name
  state                      = "Enabled"
  storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  disabled_alerts = [
    "Sql_Injection",
    "Data_Exfiltration"
  ]
  retention_days = 20
}

```