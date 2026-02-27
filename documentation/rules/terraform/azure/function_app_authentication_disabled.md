---
title: "Function App authentication disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/function_app_authentication_disabled"
  id: "e65a0733-94a0-4826-82f4-df529f4c593f"
  display_name: "Function App authentication disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `e65a0733-94a0-4826-82f4-df529f4c593f`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#auth_settings)

### Description

Azure Function App authentication settings should be enabled to ensure that only authorized users and services can access the deployed function endpoints. Leaving authentication (`auth_settings { enabled = true }`) disabled, as shown below, permits unauthenticated, potentially malicious access to the function app, increasing the risk of data exposure or unauthorized actions:

```
resource "azurerm_function_app" "example" {
  // ...other config...
  auth_settings {
    enabled = true
  }
}
```

Enabling authentication protects sensitive operations and helps prevent unauthorized or anonymous interaction with serverless workloads.

## Compliant Code Examples
```terraform
resource "azurerm_function_app" "negative" {
  name                       = "test-azure-functions"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key

   auth_settings {
    enabled = true
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_function_app" "positive2" {
  name                       = "test-azure-functions"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key

   auth_settings {
    enabled = false
  }
}

```

```terraform
resource "azurerm_function_app" "positive1" {
  name                       = "test-azure-functions"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
}

```