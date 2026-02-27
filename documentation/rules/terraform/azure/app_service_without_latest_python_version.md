---
title: "App Service without latest Python version"
group_id: "Terraform / Azure"
meta:
  name: "azure/app_service_without_latest_python_version"
  id: "cc4aaa9d-1070-461a-b519-04e00f42db8a"
  display_name: "App Service without latest Python version"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `cc4aaa9d-1070-461a-b519-04e00f42db8a`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#python_version)

### Description

It is recommended to specify the latest supported Python version for the `python_version` attribute in the `site_config` block of the `azurerm_app_service` resource. Using outdated Python versions, such as `"python_version = \"2.7\""`, exposes your application to known security vulnerabilities and prevents access to important features and security updates available in newer releases. To reduce risk, configure the resource with an up-to-date version. For example:

```
site_config {
  python_version = "3.10"
}
```

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
      python_version = "3.10"
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
      python_version = "v3.10"
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
    python_version              = "3.10"
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
      python_version = "v2.7"
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
      python_version = "2.7"
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
    python_version              = "2.7"
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