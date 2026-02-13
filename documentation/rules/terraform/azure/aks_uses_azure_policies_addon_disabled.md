---
title: "Azure Policy Add-on Disabled in AKS Cluster"
group_id: "Terraform / Azure"
meta:
  name: "azure/aks_uses_azure_policies_addon_disabled"
  id: "43789711-161b-4708-b5bb-9d1c626f7492"
  display_name: "Azure Policy Add-on Disabled in AKS Cluster"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `43789711-161b-4708-b5bb-9d1c626f7492`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#azure_policy)

### Description

Enabling the Azure Policy Add-On for Azure Kubernetes Service (AKS) clusters helps enforce organizational standards and compliance at scale by applying policy controls directly to the cluster. If the `addon_profile.azure_policy.enabled` attribute is set to `false`, as shown below, the cluster will not have Azure Policy integration, leaving it vulnerable to resource misconfigurations and violating compliance policies.

```
addon_profile {
  azure_policy {
    enabled = false
  }
}
```

To mitigate this vulnerability, the policy add-on should be enabled by setting `enabled = true`, ensuring that security and compliance policies are consistently enforced within the AKS environment.

```
addon_profile {
  azure_policy {
    enabled = true
  }
}
```

## Compliant Code Examples
```terraform
resource "azurerm_kubernetes_cluster" "negative" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"

  azure_policy_enabled = true
}

```

```terraform
resource "azurerm_kubernetes_cluster" "negative" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"

  addon_profile {

   azure_policy {

     enabled = true

   }
 }
}


```
## Non-Compliant Code Examples
```terraform
resource "azurerm_kubernetes_cluster" "positive2" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"

  azure_policy_enabled = false
}

```

```terraform
resource "azurerm_kubernetes_cluster" "positive3" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"

  addon_profile {}
}

```

```terraform
resource "azurerm_kubernetes_cluster" "positive4" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"
}

```