---
title: "Dashboard is enabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/dashboard_is_enabled"
  id: "61c3cb8b-0715-47e4-b788-86dde40dd2db"
  display_name: "Dashboard is enabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `61c3cb8b-0715-47e4-b788-86dde40dd2db`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster)

### Description

This check verifies if the Kubernetes Dashboard add-on is enabled in the cluster configuration by examining the `addon_profile` block and specifically whether `kube_dashboard { enabled = true }` has been set. Enabling the Kubernetes Dashboard can expose sensitive cluster information and administrative controls via a web interface, increasing the risk of unauthorized access if not properly secured or restricted. For better security, the dashboard should be disabled by setting `enabled = false`:

```
addon_profile {
  kube_dashboard {
    enabled = false
  }
}
```
This reduces the potential attack surface and protects against possible privilege escalation or data exposure vulnerabilities.

## Compliant Code Examples
```terraform
resource "azurerm_kubernetes_cluster" "negative1" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "Production"
  }
}

resource "azurerm_kubernetes_cluster" "negative2" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "Production"
  }

  addon_profile {
    kube_dashboard {
        enabled = false
    }
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_kubernetes_cluster" "positive1" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "Production"
  }
  
  addon_profile {
    kube_dashboard {
      enabled = true
    }
  }
}
```