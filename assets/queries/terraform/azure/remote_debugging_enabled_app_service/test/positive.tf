resource "azurerm_app_service" "bad_example" {
  name                = "bad-app-service"
  location            = "East US"
  resource_group_name = "example-rg"
  app_service_plan_id = "example-plan-id"

  site_config {
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
    min_tls_version          = ["1.2"]
  }
}

resource "azurerm_linux_function_app" "bad_example" {
  name                = "bad-linux-func-app"
  location            = "East US"
  resource_group_name = "example-rg"
  service_plan_id     = "example-plan-id"

  site_config {
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}

resource "azurerm_linux_function_app_slot" "bad_example" {
  name            = "bad-linux-func-app-slot"
  function_app_id = "example-app-service-id"

  site_config {
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}


resource "azurerm_linux_web_app_slot" "bad_example" {
  name           = "bad-linux-web-app-slot"
  app_service_id = "example-plan-id"

  site_config {
    minimum_tls_version      = ["1.2"]
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}


resource "azurerm_linux_web_app" "bad_example" {
  name                = "bad-linux-web-app"
  location            = "East US"
  resource_group_name = "example-rg"
  service_plan_id     = "example-plan-id"

  site_config {
    minimum_tls_version      = ["1.2"]
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}

resource "azurerm_windows_function_app" "bad_example" {
  name                = "bad-windows-func-app"
  location            = "East US"
  resource_group_name = "example-rg"
  service_plan_id     = "example-plan-id"

  site_config {
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}

resource "azurerm_windows_function_app_slot" "bad_example" {
  name            = "bad-windows-func-app-slot"
  function_app_id = "example-func-app"

  site_config {
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}

resource "azurerm_windows_web_app" "bad_example" {
  name                = "bad-windows-web-app"
  location            = "East US"
  resource_group_name = "example-rg"
  service_plan_id     = "example-plan-id"

  site_config {
    minimum_tls_version      = ["1.2"]
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}

resource "azurerm_windows_web_app_slot" "bad_example" {
  name           = "bad-windows-web-app-slot"
  app_service_id = "example-plan-id"

  site_config {
    minimum_tls_version      = ["1.2"]
    remote_debugging_enabled = [true] # ❌ Remote debugging enabled
  }
}
