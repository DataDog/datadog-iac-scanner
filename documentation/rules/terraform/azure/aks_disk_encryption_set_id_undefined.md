---
title: "AKS disk encryption set ID undefined"
group_id: "Terraform / Azure"
meta:
  name: "azure/aks_disk_encryption_set_id_undefined"
  id: "b17d8bb8-4c08-4785-867e-cb9e62a622aa"
  display_name: "AKS disk encryption set ID undefined"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Encryption"
---
## Metadata

**Id:** `b17d8bb8-4c08-4785-867e-cb9e62a622aa`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#disk_encryption_set_id)

### Description

 Azure Kubernetes Service (AKS) clusters should configure the `disk_encryption_set_id` attribute to ensure that managed disks are encrypted with a customer-managed key instead of the default platform-managed keys. Without this configuration, persistent data stored on cluster disks may be vulnerable to unauthorized access or data exposure, as the encryption relies only on platform defaults. For improved security, configure the AKS resource as follows:

```
resource "azurerm_kubernetes_cluster" "secure" {
  // ... other config ...
  disk_encryption_set_id = "id"
  // ... 
}
```
This ensures that sensitive container and application data on disk is encrypted according to organizational policy, reducing risks associated with data breaches.


## Compliant Code Examples
```terraform
resource "azurerm_kubernetes_cluster" "negative" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"

  disk_encryption_set_id = "id"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }
}


resource "azurerm_kubernetes_cluster2" "negative" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
    os_disk_type = "Ephemeral"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_kubernetes_cluster" "positive" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }
}

```