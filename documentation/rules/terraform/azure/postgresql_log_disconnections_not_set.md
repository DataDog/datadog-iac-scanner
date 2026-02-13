---
title: "PostgreSQL log disconnections not set"
group_id: "Terraform / Azure"
meta:
  name: "azure/postgresql_log_disconnections_not_set"
  id: "07f7134f-9f37-476e-8664-670c218e4702"
  display_name: "PostgreSQL log disconnections not set"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `07f7134f-9f37-476e-8664-670c218e4702`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration)

### Description

 The PostgreSQL server parameter `log_disconnections` controls whether session disconnections are logged, which is important for auditing and monitoring database activity. If this parameter is set to `"off"`, as shown in the configuration below, database disconnect events will not be recorded, making it significantly harder to detect unauthorized access or troubleshoot potential security incidents.

```
resource "azurerm_postgresql_configuration" "example" {
    name                = "log_disconnections"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "off"
}
```

To mitigate this risk, ensure that `log_disconnections` is configured to `"on"` in your Terraform code:

```
resource "azurerm_postgresql_configuration" "example" {
    name                = "log_disconnections"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "on"
}
```

Leaving this parameter disabled can result in blind spots in your security monitoring and incident response processes.


## Compliant Code Examples
```terraform
resource "azurerm_postgresql_configuration" "negative1" {
    name                = "log_disconnections"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "on"
}

resource "azurerm_postgresql_configuration" "negative2" {
    name                = "log_disconnections"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "On"
}

resource "azurerm_postgresql_configuration" "negative3" {
    name                = "log_disconnections"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "ON"
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_postgresql_configuration" "positive1" {
    name                = "log_disconnections"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "off"
}

resource "azurerm_postgresql_configuration" "positive2" {
    name                = "log_disconnections"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "Off"
}

resource "azurerm_postgresql_configuration" "positive3" {
    name                = "log_disconnections"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "OFF"
}
```