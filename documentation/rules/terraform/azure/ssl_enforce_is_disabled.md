---
title: "SSL enforce disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/ssl_enforce_is_disabled"
  id: "0437633b-daa6-4bbc-8526-c0d2443b946e"
  display_name: "SSL enforce disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `0437633b-daa6-4bbc-8526-c0d2443b946e`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server)

### Description

Enforcing SSL connections on PostgreSQL servers ensures all data transmitted between clients and the database is encrypted, protecting sensitive information from interception or tampering. If the `ssl_enforcement_enabled` attribute is set to `false` or omitted in Terraform, as shown below, data may be transmitted in plaintext, exposing credentials and other data to potential attackers:

```
resource "azurerm_postgresql_server" "example" {
  // ...
  ssl_enforcement_enabled = false
}
```

To secure the server, ensure `ssl_enforcement_enabled` is set to `true`:

```
resource "azurerm_postgresql_server" "example" {
  // ...
  ssl_enforcement_enabled = true
}
```
Neglecting to enforce SSL can result in data breaches or non-compliance with security standards.

## Compliant Code Examples
```terraform
resource "azurerm_postgresql_server" "negative1" {
  name                = "example-psqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladminun"
  administrator_login_password = "H@Sh1CoR3!"

  sku_name   = "GP_Gen5_4"
  version    = "9.6"
  storage_mb = 640000

  backup_retention_days        = 7
  geo_redundant_backup_enabled = true
  auto_grow_enabled            = true

  public_network_access_enabled    = false
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_postgresql_server" "positive1" {
  name                = "example-psqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladminun"
  administrator_login_password = "H@Sh1CoR3!"

  sku_name   = "GP_Gen5_4"
  version    = "9.6"
  storage_mb = 640000

  backup_retention_days        = 7
  geo_redundant_backup_enabled = true
  auto_grow_enabled            = true

  public_network_access_enabled    = false
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"
}

resource "azurerm_postgresql_server" "positive2" {
  name                = "example-psqlserver"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladminun"
  administrator_login_password = "H@Sh1CoR3!"

  sku_name   = "GP_Gen5_4"
  version    = "9.6"
  storage_mb = 640000

  backup_retention_days        = 7
  geo_redundant_backup_enabled = true
  auto_grow_enabled            = true

  public_network_access_enabled    = false
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
```