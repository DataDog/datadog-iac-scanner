---
title: "App Service managed identity disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/app_service_managed_identity_disabled"
  id: "terraform-azure-app-service-managed-identity-disabled"
  display_name: "App Service managed identity disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Resource Management"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-azure-app-service-managed-identity-disabled{{< /copyable-code >}}

**Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#identity)

### Description

Azure App Services should have managed identities enabled to provide secure, automated identity management for accessing Azure resources. Without specifying the `identity { type = "SystemAssigned" }` block in the Terraform configuration, the service may rely on insecure credential storage or hardcoded secrets, increasing the risk of credential exposure. Enabling managed identity ensures the App Service can securely authenticate to Azure resources without the need to manage credentials manually, reducing the attack surface and enhancing overall security.

```
resource "azurerm_app_service" "example" {
  // ...other configuration...

  identity {
    type = "SystemAssigned"
  }
}
```

## Compliant Code Examples
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

  app_settings = {
    "SOME_KEY" = "some-value"
  }

  connection_string {
    name  = "Database"
    type  = "SQLServer"
    value = "Server=some-server.mydomain.com;Integrated Security=SSPI"
  }

  identity {
    type = "SystemAssigned"
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