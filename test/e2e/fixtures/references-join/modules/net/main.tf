variable "n" {
  type = number
}

resource "aws_subnet" "s" {
  count      = 3
  cidr_block = "10.0.${count.index}.0/24"
}

resource "azurerm_subnet_network_security_group_association" "s" {
  count     = var.n
  subnet_id = aws_subnet.s[count.index].id
}
