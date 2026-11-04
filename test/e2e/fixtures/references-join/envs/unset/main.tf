variable "unset" {
  type = string
}

resource "aws_subnet" "s" {
  cidr_block = "10.1.0.0/24"
}

resource "azurerm_subnet_network_security_group_association" "s" {
  subnet_id = var.unset
}
