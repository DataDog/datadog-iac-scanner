---
title: "App Service FTPS enforce disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/app_service_ftps_enforce_disabled"
  id: "85da374f-b00f-4832-9d44-84a1ca1e89f8"
  display_name: "App Service FTPS enforce disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `85da374f-b00f-4832-9d44-84a1ca1e89f8`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#ftps_state)

### Description

App Service FTPS enforcement should be configured by setting the `ftps_state` attribute to `"FtpsOnly"` in the `site_config` block for the `azurerm_app_service` resource. Allowing `"AllAllowed"` in this setting permits both unencrypted FTP and encrypted FTPS connections, exposing sensitive data to potential interception or tampering during transit. To ensure data confidentiality and compliance, always use:

```
ftps_state = "FtpsOnly"
```
This setting enforces encrypted connections to the Azure App Service.

## Compliant Code Examples
```terraform
resource "azurerm_app_service" "negative2" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    ftps_state = "Disabled"
  }
}

```

```terraform
resource "azurerm_app_service" "negative1" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    ftps_state = "FtpsOnly"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_app_service" "positive1" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    ftps_state = "AllAllowed"
  }
}

```