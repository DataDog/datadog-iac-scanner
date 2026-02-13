# Failing example 1: Attribute exists but is set to true.
resource "azurerm_postgresql_server" "bad_example" {
  name                = "bad-postgresql-server"
  location            = "East US"
  resource_group_name = "example-rg"

  public_network_access_enabled = [true] # ❌ Should be false

  version                 = "9.6"
  ssl_enforcement_enabled = true
  sku_name                = "B_Gen5_1"
}

# Failing example 2: Attribute is missing.
resource "azurerm_postgresql_server" "bad_example_missing" {
  name                = "bad-postgresql-server-missing"
  location            = "East US"
  resource_group_name = "example-rg"
  # public_network_access_enabled is not defined → ❌ Violation

  version                 = "9.6"
  ssl_enforcement_enabled = true
  sku_name                = "B_Gen5_1"
}
