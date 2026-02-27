---
title: "Azure App Service client certificate disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/azure_app_service_client_certificate_disabled"
  id: "a81573f9-3691-4d83-88a0-7d4af63e17a3"
  display_name: "Azure App Service client certificate disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `a81573f9-3691-4d83-88a0-7d4af63e17a3`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#client_cert_enabled)

### Description

Enabling client certificates for Azure App Service ensures that only authenticated clients can access the application by requiring a client SSL certificate in all HTTPS requests. If the `client_cert_enabled` attribute is not set to `true`, unauthorized users could potentially connect to the service, increasing the risk of data leaks or abuse. To secure the App Service, always configure the resource as follows:

```
resource "azurerm_app_service" "example" {
  // ... other configuration ...
  client_cert_enabled = true
}
```

## Compliant Code Examples
```terraform
resource "azurerm_app_service" "negative" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
  }

  app_settings = {
    SOME_KEY = "some-value"
  }

  client_cert_enabled = true

  connection_string {
    name  = "Database"
    type  = "SQLServer"
    value = "Server=some-server.mydomain.com;Integrated Security=SSPI"
  }
}


```
## Non-Compliant Code Examples
```terraform
resource "azurerm_app_service" "positive2" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
  }

  app_settings = {
    SOME_KEY = "some-value"
  }

  client_cert_enabled = false

  connection_string {
    name  = "Database"
    type  = "SQLServer"
    value = "Server=some-server.mydomain.com;Integrated Security=SSPI"
  }
}

```

```terraform
resource "azurerm_app_service" "positive1" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
  }

  app_settings = {
    SOME_KEY = "some-value"
  }

  connection_string {
    name  = "Database"
    type  = "SQLServer"
    value = "Server=some-server.mydomain.com;Integrated Security=SSPI"
  }
}

```