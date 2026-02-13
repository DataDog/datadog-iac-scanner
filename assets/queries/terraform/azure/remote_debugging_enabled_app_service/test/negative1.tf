
resource "azurerm_linux_web_app" "good_example" {
  name                = "good-linux-web-app"
  location            = "East US"
  resource_group_name = "example-rg"
  service_plan_id     = "example-plan-id"

  site_config {
    minimum_tls_version      = ["1.2"]
    remote_debugging_enabled = [false] # ✅ Remote debugging disabled
  }
}
