---
title: "Network interfaces with public IP"
group_id: "Terraform / Azure"
meta:
  name: "azure/network_interfaces_with_public_ip"
  id: "terraform-azure-network-interfaces-with-public-ip"
  display_name: "Network interfaces with public IP"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-azure-network-interfaces-with-public-ip{{< /copyable-code >}}

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_interface#public_ip_address_id)

### Description

Exposing network interfaces with a public IP address in Terraform (`public_ip_address_id` attribute) can introduce significant security risks, as it enables direct access from the internet to associated resources, increasing the attack surface for unauthorized access and attacks. If a public IP is required, additional controls and security baselines should be strictly enforced to minimize exposure. To enhance security, network interfaces should be defined without the `public_ip_address_id` field, as shown below:

```
resource "azurerm_network_interface" "secure" {
  name                = "example-nic"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
  }
}
```

## Compliant Code Examples
```terraform
resource "azurerm_network_interface" "negative" {
  name                = "example-nic"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_network_interface" "positive" {
  name                = "example-nic"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = "IP"
  }
}

```