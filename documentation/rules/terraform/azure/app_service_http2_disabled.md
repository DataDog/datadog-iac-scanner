---
title: "App Service HTTP2 disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/app_service_http2_disabled"
  id: "525b53be-62ed-4244-b4df-41aecfcb4071"
  display_name: "App Service HTTP2 disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `525b53be-62ed-4244-b4df-41aecfcb4071`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#http2_enabled)

### Description

 Enabling HTTP/2 for Azure App Service is essential for improved security and performance, as HTTP/2 offers better data encryption, reduced latency, and protection against certain protocol-level attacks. If the `http2_enabled` attribute is not set to `true` in the `site_config` block, as shown below, the app service will only support HTTP/1.1, making it more vulnerable to downgrade attacks and less efficient in handling modern web traffic.

```
site_config {
  http2_enabled = true
}
```
Neglecting to enable HTTP/2 may expose applications to increased risks and degrade the overall performance and user experience.


## Compliant Code Examples
```terraform
resource "azurerm_app_service" "negative" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  app_settings = {
    "SOME_KEY" = "some-value"
  }

  connection_string {
    name  = "Database"
    type  = "SQLServer"
    value = "Server=some-server.mydomain.com;Integrated Security=SSPI"
  }

  site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    min_tls_version = 1.2
    http2_enabled = true
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

  app_settings = {
    "SOME_KEY" = "some-value"
  }

  connection_string {
    name  = "Database"
    type  = "SQLServer"
    value = "Server=some-server.mydomain.com;Integrated Security=SSPI"
  }

  site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    min_tls_version = 1.2
  }
}

```

```terraform
resource "azurerm_app_service" "positive3" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

  app_settings = {
    "SOME_KEY" = "some-value"
  }

  connection_string {
    name  = "Database"
    type  = "SQLServer"
    value = "Server=some-server.mydomain.com;Integrated Security=SSPI"
  }

  site_config {
    dotnet_framework_version = "v4.0"
    scm_type                 = "LocalGit"
    min_tls_version = 1.2
    http2_enabled = false
  }
}

```

```terraform
resource "azurerm_app_service" "positive1" {
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id

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