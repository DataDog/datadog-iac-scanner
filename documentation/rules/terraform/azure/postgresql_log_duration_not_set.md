---
title: "PostgreSQL log duration not set"
group_id: "Terraform / Azure"
meta:
  name: "azure/postgresql_log_duration_not_set"
  id: "16e0879a-c4ae-4ff8-a67d-a2eed5d67b8f"
  display_name: "PostgreSQL log duration not set"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `16e0879a-c4ae-4ff8-a67d-a2eed5d67b8f`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration)

### Description

 The PostgreSQL server parameter `log_duration` should be set to `ON` to ensure that the duration of each completed SQL statement is logged. Without this setting enabled (for example, if `value = "off"` is used in the `azurerm_postgresql_configuration` resource), critical visibility into query performance and potential issues will be lost, making it difficult to identify slow-running queries or investigate security incidents. Setting `log_duration` to `ON`, as shown below, enables enhanced monitoring and auditing capabilities for your database:

```
resource "azurerm_postgresql_configuration" "secure_example" {
    name                = "log_duration"
    resource_group_name = "example_resource_group_name"
    server_name         = "example_server_name"
    value               = "ON"
}
```


## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
resource "azurerm_postgresql_configuration" "negative1" {
    name                = "log_duration"
    resource_group_name = "example1_resource_group_name"
    server_name         = "example1_server_name"
    value               = "on"
}

resource "azurerm_postgresql_configuration" "negative2" {
    name                = "log_duration"
    resource_group_name = "example2_resource_group_name"
    server_name         = "example2_server_name"
    value               = "On"
}

resource "azurerm_postgresql_configuration" "negative3" {
    name                = "log_duration"
    resource_group_name = "example3_resource_group_name"
    server_name         = "example3_server_name"
    value               = "ON"
}
```
## Non-Compliant Code Examples
```terraform
#this is a problematic code where the query should report a result(s)
resource "azurerm_postgresql_configuration" "positive1" {
    name                = "log_duration"
    resource_group_name = "example1_resource_group_name"
    server_name         = "example1_server_name"
    value               = "off"
}

resource "azurerm_postgresql_configuration" "positive2" {
    name                = "log_duration"
    resource_group_name = "example2_resource_group_name"
    server_name         = "example2_server_name"
    value               = "Off"
}

resource "azurerm_postgresql_configuration" "positive3" {
    name                = "log_duration"
    resource_group_name = "example3_resource_group_name"
    server_name         = "example3_server_name"
    value               = "OFF"
}
```