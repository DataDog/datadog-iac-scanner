resource "azurerm_mysql_server" "good_example" {
  name                = "good-mysql-server"
  location            = "East US"
  resource_group_name = "example-rg"

  ssl_minimal_tls_version_enforced = ["TLS1_2"] # ✅ Correct TLS version
}
