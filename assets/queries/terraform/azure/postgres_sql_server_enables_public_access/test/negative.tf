resource "azurerm_postgresql_server" "good_example" {
  name                = "good-postgresql-server"
  location            = "East US"
  resource_group_name = "example-rg"

  public_network_access_enabled = [false] # ✅ Correct setting

  version                 = "9.6"
  ssl_enforcement_enabled = true
  sku_name                = "B_Gen5_1"
}
