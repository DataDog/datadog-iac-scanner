---
title: "AKS network policy misconfigured"
group_id: "Terraform / Azure"
meta:
  name: "azure/aks_network_policy_misconfigured"
  id: "f5342045-b935-402d-adf1-8dbbd09c0eef"
  display_name: "AKS network policy misconfigured"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `f5342045-b935-402d-adf1-8dbbd09c0eef`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/kubernetes_cluster)

### Description

 Azure Kubernetes Service (AKS) clusters should have a proper network policy configured using the `network_profile.network_policy` attribute to enforce the principle of least privilege and restrict unnecessary network traffic between pods. If this attribute is omitted or misconfigured, as shown below, it leaves the cluster vulnerable to unrestricted communication between pods, increasing the risk of lateral movement and exposure if one pod is compromised:

```
network_profile {
  // network_policy not defined
}
```

A secure AKS configuration explicitly sets a network policy. For example:

```
network_profile {
  network_policy = "azure"
}
```
Without strict network policies, attackers could exploit insecure inter-pod communications to access sensitive resources or escalate privileges within the Kubernetes environment.


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

  network_profile {
    network_policy = "azure"
  }
}

resource "azurerm_kubernetes_cluster" "negative2" {
  name                = "example-aks2"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks2"

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

  network_profile {
    network_policy = "calico"
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

  network_profile {
    #...other configurations
  }
}

resource "azurerm_kubernetes_cluster" "positive2" {
  name                = "example-aks2"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks2"

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

resource "azurerm_kubernetes_cluster" "positive3" {
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

  network_profile {
    network_policy = "roxanne"
  }
}
```