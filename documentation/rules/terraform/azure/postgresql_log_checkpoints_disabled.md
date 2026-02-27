---
title: "PostgreSQL log checkpoints disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/postgresql_log_checkpoints_disabled"
  id: "3790d386-be81-4dcf-9850-eaa7df6c10d9"
  display_name: "PostgreSQL log checkpoints disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `3790d386-be81-4dcf-9850-eaa7df6c10d9`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration)

### Description

The PostgreSQL `log_checkpoints` parameter controls whether checkpoint activities are logged, which is critical for monitoring and troubleshooting database performance and reliability. If `log_checkpoints` is set to `off`, important information about checkpoint events will not be recorded, making it more difficult to detect or respond to potential issues or attacks. To mitigate this risk, the parameter should be enabled, as shown below:

```
resource "azurerm_postgresql_configuration" "secure_example" {
    name                = "log_checkpoints"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "on"
}
```

Failing to enable this logging may leave administrators unaware of problems that can impact data durability or signal malicious activity, increasing the risk of unnoticed outages or data loss.

## Compliant Code Examples
```terraform
resource "azurerm_postgresql_configuration" "negative1" {
    name                = "log_checkpoints"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "on"
}

resource "azurerm_postgresql_configuration" "negative2" {
    name                = "log_checkpoints"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "On"
}

resource "azurerm_postgresql_configuration" "negative3" {
    name                = "log_checkpoints"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "ON"
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_postgresql_configuration" "positive1" {
    name                = "log_checkpoints"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "off"
}

resource "azurerm_postgresql_configuration" "positive2" {
    name                = "log_checkpoints"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "Off"
}

resource "azurerm_postgresql_configuration" "positive3" {
    name                = "log_checkpoints"
    resource_group_name = data.azurerm_resource_group.example.name
    server_name         = azurerm_postgresql_server.example.name
    value               = "OFF"
}
```