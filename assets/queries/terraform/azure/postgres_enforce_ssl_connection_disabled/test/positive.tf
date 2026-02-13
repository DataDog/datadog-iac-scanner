resource "azurerm_postgresql_server" "bad_example" {
  name                = "bad-postgresql-server"
  location            = "East US"
  resource_group_name = "example-rg"
  sku_name            = "B_Gen5_1"
  version             = "9.6"

  ssl_enforcement_enabled = ["DISABLED"] # ❌ SSL enforcement is not enabled
}
