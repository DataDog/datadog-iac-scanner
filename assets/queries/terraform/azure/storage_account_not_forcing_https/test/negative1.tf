resource "azurerm_storage_account" "positive2" {
  name                     = "example2"
  resource_group_name      = data.azurerm_resource_group.example.name
  location                 = data.azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  # will not flag because https_traffic_only_enabled is set to true by default so we do not error
}
