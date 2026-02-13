# Passing example: Correct enforcement and TLS settings
resource "azurerm_mariadb_server" "good_example" {
  name                = "good-mariadb-server"
  location            = "East US"
  resource_group_name = "example-rg"

  ssl_enforcement_enabled          = ["true"]
  ssl_minimal_tls_version_enforced = ["TLS1_2"] # Correct setting
}
