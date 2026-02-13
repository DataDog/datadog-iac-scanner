# Passing example: ssl_minimal_tls_version_enforced not defined (defaults to TLS1_2)
resource "azurerm_mariadb_server" "good_example_default" {
  name                = "good-mariadb-server-default"
  location            = "East US"
  resource_group_name = "example-rg"

  ssl_enforcement_enabled = ["true"]
  # ssl_minimal_tls_version_enforced not specified → defaults to TLS1_2
}
