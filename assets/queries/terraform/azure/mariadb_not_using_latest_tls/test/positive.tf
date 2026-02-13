# Failing example: ssl_enforcement_enabled is not "true"
resource "azurerm_mariadb_server" "bad_example" {
  name                = "bad-mariadb-server"
  location            = "East US"
  resource_group_name = "example-rg"

  ssl_enforcement_enabled          = ["false"]  # ❌ Incorrect value
  ssl_minimal_tls_version_enforced = ["TLS1_2"] # Even if TLS is correct, enforcement flag is wrong
}

# Failing example: ssl_enforcement_enabled is "true" but minimal TLS is set incorrectly
resource "azurerm_mariadb_server" "bad_example2" {
  name                = "bad-mariadb-server-2"
  location            = "East US"
  resource_group_name = "example-rg"

  ssl_enforcement_enabled          = ["true"]
  ssl_minimal_tls_version_enforced = ["TLS1_0"] # ❌ Incorrect TLS version
}
