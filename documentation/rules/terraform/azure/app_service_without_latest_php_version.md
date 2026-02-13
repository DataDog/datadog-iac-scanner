---
title: "App Service without latest PHP version"
group_id: "Terraform / Azure"
meta:
  name: "azure/app_service_without_latest_php_version"
  id: "96fe318e-d631-4156-99fa-9080d57280ae"
  display_name: "App Service without latest PHP version"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `96fe318e-d631-4156-99fa-9080d57280ae`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#php_version)

### Description

Web apps using outdated PHP versions expose themselves to known security vulnerabilities and miss out on critical security fixes and performance improvements available in newer releases. For example, specifying `php_version = "7.3"` in a Terraform `azurerm_app_service` resource leaves the application open to exploits that are resolved in later PHP versions. To mitigate risk, always configure the `site_config` block to use a recent, supported PHP version, such as in the following example:

```
site_config {
  php_version = "8.1"
}
```
This ensures the application benefits from the latest patches and features.

## Compliant Code Examples
```terraform
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_service_plan" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku_name            = "P1v2"
}

resource "azurerm_linux_web_app" "example3" {
  name                = "example3"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_service_plan.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config{
    application_stack{
      php_version = "8.1"
    }    
  }
}

```

```terraform
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_service_plan" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku_name            = "P1v2"
}

resource "azurerm_windows_web_app" "example2" {
  name                = "example2"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_service_plan.example.location
  service_plan_id     = azurerm_service_plan.example.id

   site_config{
    application_stack{
      php_version = "v8.1"
    }    
  }
}

```

```terraform
resource "azurerm_app_service" "example1" {
  name                = "example1-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
  
  # SiteConfig block is optional before AzureRM version 3.0 
  site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    php_version              = "8.1"
  }

  app_settings = {
    "SOME_KEY" = "some-value"
  }

  connection_string {
    name  = "Database"
    type  = "SQLServer"
    value = "Server=some-server.mydomain.com;Integrated Security=SSPI"
  }
}

```
## Non-Compliant Code Examples
```terraform
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_service_plan" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku_name            = "P1v2"
}

resource "azurerm_windows_web_app" "example5" {
  name                = "example5"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_service_plan.example.location
  service_plan_id     = azurerm_service_plan.example.id

   site_config{
    application_stack{
      php_version = "v7.3"
    }    
  }
}

```

```terraform
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_service_plan" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  os_type             = "Linux"
  sku_name            = "P1v2"
}

resource "azurerm_linux_web_app" "example6" {
  name                = "example6"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_service_plan.example.location
  service_plan_id     = azurerm_service_plan.example.id

  site_config{
    application_stack{
      php_version = "7.4"
    }    
  }
}

```

```terraform
resource "azurerm_app_service" "example4" {
  name                = "example4-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  # SiteConfig block is optional before AzureRM version 3.0 
  site_config { 
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    php_version              = "7.3"
  }

  app_settings = {
    "SOME_KEY" = "some-value"
  }

  connection_string {
    name  = "Database"
    type  = "SQLServer"
    value = "Server=some-server.mydomain.com;Integrated Security=SSPI"
  }
}

```