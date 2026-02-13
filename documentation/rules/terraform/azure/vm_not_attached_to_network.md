---
title: "VM not attached to network"
group_id: "Terraform / Azure"
meta:
  name: "azure/vm_not_attached_to_network"
  id: "bbf6b3df-4b65-4f87-82cc-da9f30f8c033"
  display_name: "VM not attached to network"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `bbf6b3df-4b65-4f87-82cc-da9f30f8c033`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#network_interface_ids)

### Description

 Attaching a Network Security Group (NSG) to a virtual machine in Azure is essential for defining and restricting inbound and outbound traffic. Without an NSG, as in the configuration below where `network_interface_ids` is set to an empty list and no NSG is associated, the virtual machine is left exposed to unrestricted network access, increasing the risk of unauthorized access and potential security breaches.

```
resource "azurerm_virtual_machine" "example" {
  name                  = "example-vm"
  location              = azurerm_resource_group.example.location
  resource_group_name   = azurerm_resource_group.example.name
  network_interface_ids = []
  vm_size               = "Standard_DS1_v2"
}
```

To mitigate this risk, ensure NSGs are attached by associating them with the network interface connected to the VM, as shown below:

```
resource "azurerm_network_interface" "example" {
  name                = "example-nic"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_interface_security_group_association" "example" {
  network_interface_id      = azurerm_network_interface.example.id
  network_security_group_id = azurerm_network_security_group.example.id
}
```

Neglecting to configure and attach an NSG can result in unrestricted network exposure for the VM, leading to increased vulnerability to attacks, unauthorized access, and data breaches.


## Compliant Code Examples
```terraform
resource "azurerm_network_interface" "negative1" {
  name                = "${var.prefix}-nic"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  ip_configuration {
    name                          = "testconfiguration1"
    subnet_id                     = azurerm_subnet.internal.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_virtual_machine" "negative2" {
  name                  = "${var.prefix}-vm"
  location              = azurerm_resource_group.main.location
  resource_group_name   = azurerm_resource_group.main.name
  network_interface_ids = [azurerm_network_interface.main.id]
  vm_size               = "Standard_DS1_v2"

  os_profile_linux_config {
    disable_password_authentication = false
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_virtual_machine" "positive1" {
  name                  = "${var.prefix}-vm"
  location              = azurerm_resource_group.main.location
  resource_group_name   = azurerm_resource_group.main.name
  network_interface_ids = []
  vm_size               = "Standard_DS1_v2"

  os_profile_linux_config {
    disable_password_authentication = false
  }
}
```