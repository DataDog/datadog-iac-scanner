---
title: "PostgreSQL server without connection throttling"
group_id: "Terraform / Azure"
meta:
  name: "azure/postgresql_server_without_connection_throttling"
  id: "2b3c671f-1b76-4741-8789-ed1fe0785dc4"
  display_name: "PostgreSQL server without connection throttling"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `2b3c671f-1b76-4741-8789-ed1fe0785dc4`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration)

### Description

PostgreSQL servers should have connection throttling enabled by setting the `connection_throttling` configuration value to `"on"`. Without connection throttling (for example, `value = "off"`), the server is more vulnerable to connection floods and denial-of-service attacks, as there is no mechanism to limit the rate of incoming connections. Enabling this option reduces the risk of service disruption by preventing excessive connection attempts from overloading the database.

A secure Terraform configuration example is shown below:
  
```
resource "azurerm_postgresql_configuration" "example" {
    name                = "connection_throttling"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "on"
}
```

## Compliant Code Examples
```terraform
resource "azurerm_postgresql_configuration" "negative1" {
    name                = "connection_throttling"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "on"
}

resource "azurerm_postgresql_configuration" "negative2" {
    name                = "connection_throttling"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "On"
}

resource "azurerm_postgresql_configuration" "negative3" {
    name                = "connection_throttling"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "ON"
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_postgresql_configuration" "positive1" {
    name                = "connection_throttling"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "off"
}

resource "azurerm_postgresql_configuration" "positive2" {
    name                = "connection_throttling"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "Off"
}

resource "azurerm_postgresql_configuration" "positive3" {
    name                = "connection_throttling"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "OFF"
}
```