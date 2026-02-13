---
title: "App Service not using latest TLS encryption version"
group_id: "Terraform / Azure"
meta:
  name: "azure/app_service_not_using_latest_tls_encryption_version"
  id: "b7b9d1c7-2d3b-49b4-b867-ebbe68d0b643"
  display_name: "App Service not using latest TLS encryption version"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `b7b9d1c7-2d3b-49b4-b867-ebbe68d0b643`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#min_tls_version)

### Description

 App Service instances should be configured to use the latest version of TLS encryption to ensure secure data transmission. Using outdated TLS versions, such as setting `min_tls_version = 1.1`, exposes applications to vulnerabilities and known exploits that exist in deprecated protocols. Setting `min_tls_version = "1.2"` in the `site_config` block helps protect data in transit and reduces the risk of security breaches due to weaker encryption standards.

```
resource "azurerm_app_service" "example" {
  // ...
  site_config {
    min_tls_version = "1.2"
  }
}
```


## Compliant Code Examples
```terraform
resource "azurerm_app_service" "negative3" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
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
    min_tls_version = 1.2
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
    min_tls_version          = 1.1
  }
}

```