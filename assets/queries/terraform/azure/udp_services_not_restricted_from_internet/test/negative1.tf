# Example for azurerm_network_security_rule (standalone)
resource "azurerm_network_security_rule" "good_example_rule" {
  name                        = "Allow UDP Inbound"
  resource_group_name         = "example-rg"
  network_security_group_name = "good-nsg"
  priority                    = 100
  direction                   = "inbound"
  access                      = "allow"
  protocol                    = "udp"
  source_address_prefix       = "192.168.1.0/24" # ✅ Restricted access
  destination_address_prefix  = "*"
  source_port_range           = "*"
  destination_port_range      = "53"
}
