resource "azurerm_mysql_server" "bad_example" {
  name                = "bad-mysql-server"
  location            = "East US"
  resource_group_name = "example-rg"

  ssl_minimal_tls_version_enforced = ["TLS1_0"] # ❌ Outdated TLS version
}
