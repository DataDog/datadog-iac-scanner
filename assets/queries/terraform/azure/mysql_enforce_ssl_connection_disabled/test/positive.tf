resource "azurerm_mysql_server" "bad_example" {
  name                = "bad-mysql-server"
  location            = "East US"
  resource_group_name = "example-rg"

  ssl_enforcement_enabled = ["DISABLED"] # ❌ SSL enforcement is not enabled
}
