resource "azurerm_storage_account" "good_example" {
  name                     = "goodstorageacct"
  resource_group_name      = "example-rg"
  location                 = "East US"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags = {
    team        = "DevOps" # Required tag is present
    environment = "prod"
  }
}
