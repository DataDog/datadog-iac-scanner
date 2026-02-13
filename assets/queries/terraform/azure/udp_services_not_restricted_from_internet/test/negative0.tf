# Example for azurerm_network_security_group (embedded security_rule)
resource "azurerm_network_security_group" "good_example" {
  name                = "good-nsg"
  location            = "East US"
  resource_group_name = "example-rg"

  security_rule {
    name                       = "Allow UDP Inbound"
    protocol                   = "udp"
    direction                  = "inbound"
    access                     = "allow"
    priority                   = 100
    source_address_prefix      = "192.168.1.0/24" # ✅ Restricted access
    destination_address_prefix = "*"
    source_port_range          = "*"
    destination_port_range     = "53"
  }
}

