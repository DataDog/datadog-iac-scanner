resource "azurerm_network_security_group" "bad_example" {
  name                = "bad-nsg"
  location            = "East US"
  resource_group_name = "example-rg"

  security_rule {
    name                       = "Allow UDP Inbound"
    protocol                   = "udp"
    direction                  = "inbound"
    access                     = "allow"
    priority                   = 100
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
    source_port_range          = "*"
    destination_port_range     = "53"
  }
}

resource "azurerm_network_security_rule" "bad_example_rule" {
  name                        = "Allow UDP Inbound"
  resource_group_name         = "example-rg"
  network_security_group_name = "bad-nsg"
  priority                    = 100
  direction                   = "inbound"
  access                      = "allow"
  protocol                    = "udp"
  source_address_prefix       = "0.0.0.0/0"
  destination_address_prefix  = "*"
  source_port_range           = "*"
  destination_port_range      = "53"
}
