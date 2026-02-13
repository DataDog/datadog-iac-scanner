# Example 1: Missing tags block entirely
resource "azurerm_storage_account" "bad_example_no_tags" {
  name                     = "badstorageacct"
  resource_group_name      = "example-rg"
  location                 = "East US"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# Example 2: Tags block exists, but missing the "team" tag
resource "azurerm_storage_account" "bad_example_missing_team" {
  name                     = "badstorageacct2"
  resource_group_name      = "example-rg"
  location                 = "East US"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags = {
    environment = "prod"
  }
}
