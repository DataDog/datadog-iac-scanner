---
title: "Ensure web app is not remotely debuggable"
group_id: "Terraform / Azure"
meta:
  name: "azure/remote_debugging_enabled_app_service"
  id: "e3f7a9b0-c1d2-3e4f-5678-90abcdef1234"
  display_name: "Ensure web app is not remotely debuggable"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `e3f7a9b0-c1d2-3e4f-5678-90abcdef1234`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#site_config)

### Description

 Remote debugging in Azure app services creates a direct channel into your application which can be exploited by attackers to access sensitive data, execute arbitrary code, or gain unauthorized system access. When enabled, it significantly expands your attack surface by exposing debugging interfaces that should never be accessible in production environments. To secure your application, ensure remote debugging is explicitly disabled in your Terraform configuration by setting `remote_debugging_enabled = [false]` in the site_config block, as shown in this secure example: ```resource "azurerm_app_service" "good_example" { site_config { remote_debugging_enabled = [false] } }```.


## Compliant Code Examples
```terraform

resource "azurerm_linux_web_app" "good_example" {
  name                = "good-linux-web-app"
  location            = "East US"
  resource_group_name = "example-rg"
  service_plan_id     = "example-plan-id"

  site_config {
    minimum_tls_version      = ["1.2"]
    remote_debugging_enabled = [false] # ✅ Remote debugging disabled
  }
}

```

```terraform
resource "azurerm_app_service" "good_example" {
  name                = "good-app-service"
  location            = "East US"
  resource_group_name = "example-rg"
  app_service_plan_id = "example-plan-id"

  site_config {
    remote_debugging_enabled = [false] # ✅ Remote debugging disabled
    min_tls_version          = ["1.2"]
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_app_service" "bad_example" {
  name                = "bad-app-service"
  location            = "East US"
  resource_group_name = "example-rg"
  app_service_plan_id = "example-plan-id"

  site_config {
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
    min_tls_version          = ["1.2"]
  }
}

resource "azurerm_linux_function_app" "bad_example" {
  name                = "bad-linux-func-app"
  location            = "East US"
  resource_group_name = "example-rg"
  service_plan_id     = "example-plan-id"

  site_config {
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}

resource "azurerm_linux_function_app_slot" "bad_example" {
  name            = "bad-linux-func-app-slot"
  function_app_id = "example-app-service-id"

  site_config {
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}


resource "azurerm_linux_web_app_slot" "bad_example" {
  name           = "bad-linux-web-app-slot"
  app_service_id = "example-plan-id"

  site_config {
    minimum_tls_version      = ["1.2"]
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}


resource "azurerm_linux_web_app" "bad_example" {
  name                = "bad-linux-web-app"
  location            = "East US"
  resource_group_name = "example-rg"
  service_plan_id     = "example-plan-id"

  site_config {
    minimum_tls_version      = ["1.2"]
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}

resource "azurerm_windows_function_app" "bad_example" {
  name                = "bad-windows-func-app"
  location            = "East US"
  resource_group_name = "example-rg"
  service_plan_id     = "example-plan-id"

  site_config {
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}

resource "azurerm_windows_function_app_slot" "bad_example" {
  name            = "bad-windows-func-app-slot"
  function_app_id = "example-func-app"

  site_config {
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}

resource "azurerm_windows_web_app" "bad_example" {
  name                = "bad-windows-web-app"
  location            = "East US"
  resource_group_name = "example-rg"
  service_plan_id     = "example-plan-id"

  site_config {
    minimum_tls_version      = ["1.2"]
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}

resource "azurerm_windows_web_app_slot" "bad_example" {
  name           = "bad-windows-web-app-slot"
  app_service_id = "example-plan-id"

  site_config {
    minimum_tls_version      = ["1.2"]
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}

```