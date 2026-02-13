resource "azurerm_app_service" "good_example" {
  name                = "good-app-service"
  location            = "East US"
  resource_group_name = "example-rg"
  app_service_plan_id = "example-plan-id"

  site_config {
    remote_debugging_enabled = [false] # ✅ Remote debugging disabled
    min_tls_version          = ["1.2"]
  }
}
