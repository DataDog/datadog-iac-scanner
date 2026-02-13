---
title: "Function App FTPS enforce disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/function_app_ftps_enforce_disabled"
  id: "9dab0179-433d-4dff-af8f-0091025691df"
  display_name: "Function App FTPS enforce disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `9dab0179-433d-4dff-af8f-0091025691df`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#ftps_state)

### Description

The `ftps_state` attribute within the `site_config` block of an Azure Function App resource controls the enforcement of FTPS (FTP over SSL/TLS) for data transfer. If set to `"AllAllowed"`, both unencrypted FTP and secure FTPS connections are permitted, exposing sensitive data in transit to interception or tampering. To ensure secure data transmission, this attribute should be configured as `ftps_state = "FtpsOnly"`:

```
site_config {
  ftps_state = "FtpsOnly"
}
```

## Compliant Code Examples
```terraform
resource "azurerm_function_app" "negative2" {
  name                       = "test-azure-functions"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key

   site_config {
    ftps_state = "Disabled"
  }
}

```

```terraform
resource "azurerm_function_app" "negative1" {
  name                       = "test-azure-functions"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key

   site_config {
    ftps_state = "FtpsOnly"
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

   site_config {
    http2_enabled = true
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

   site_config {
    http2_enabled = true
    ftps_state = "AllAllowed"
  }
}

```