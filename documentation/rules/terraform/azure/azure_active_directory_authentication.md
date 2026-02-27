---
title: "Azure Active Directory authentication"
group_id: "Terraform / Azure"
meta:
  name: "azure/azure_active_directory_authentication"
  id: "a21c8da9-41bf-40cf-941d-330cf0d11fc7"
  display_name: "Azure Active Directory authentication"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Access Control"
---
## Metadata

**Id:** `a21c8da9-41bf-40cf-941d-330cf0d11fc7`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/service_fabric_cluster#tenant_id)

### Description

Azure Service Fabric clusters should be configured to use Azure Active Directory (AAD) for authentication to ensure secure identity management and access control. Omitting the `tenant_id` attribute in the `azure_active_directory` block, as shown below, may result in incomplete AAD integration, potentially allowing unauthorized access to the Service Fabric cluster:

```
azure_active_directory {
  cluster_application_id = "id"
  client_application_id = "id"
}
```

To enforce proper authentication, always specify the `tenant_id` alongside the application IDs:

```
azure_active_directory {
  tenant_id = "id"
  cluster_application_id = "id"
  client_application_id = "id"
}
```

Failure to correctly implement AAD authentication increases the risk of unauthorized cluster access and potential exposure of sensitive workloads and management endpoints.

## Compliant Code Examples
```terraform
resource "azurerm_service_fabric_cluster" "negative" {
  name                 = "example-servicefabric"
  resource_group_name  = azurerm_resource_group.example.name
  location             = azurerm_resource_group.example.location
  reliability_level    = "Bronze"
  upgrade_mode         = "Manual"
  cluster_code_version = "7.1.456.959"
  vm_image             = "Windows"
  management_endpoint  = "https://example:80"

  node_type {
    name                 = "first"
    instance_count       = 3
    is_primary           = true
    client_endpoint_port = 2020
    http_endpoint_port   = 80
  }

  azure_active_directory {
    tenant_id = "id"
    cluster_application_id = "id"
    client_application_id = "id"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_service_fabric_cluster" "positive2" {
  name                 = "example-servicefabric"
  resource_group_name  = azurerm_resource_group.example.name
  location             = azurerm_resource_group.example.location
  reliability_level    = "Bronze"
  upgrade_mode         = "Manual"
  cluster_code_version = "7.1.456.959"
  vm_image             = "Windows"
  management_endpoint  = "https://example:80"

  node_type {
    name                 = "first"
    instance_count       = 3
    is_primary           = true
    client_endpoint_port = 2020
    http_endpoint_port   = 80
  }
}

```

```terraform
resource "azurerm_service_fabric_cluster" "positive1" {
  name                 = "example-servicefabric"
  resource_group_name  = azurerm_resource_group.example.name
  location             = azurerm_resource_group.example.location
  reliability_level    = "Bronze"
  upgrade_mode         = "Manual"
  cluster_code_version = "7.1.456.959"
  vm_image             = "Windows"
  management_endpoint  = "https://example:80"

  node_type {
    name                 = "first"
    instance_count       = 3
    is_primary           = true
    client_endpoint_port = 2020
    http_endpoint_port   = 80
  }

  azure_active_directory {
    cluster_application_id = "id"
    client_application_id = "id"
  }
}

```