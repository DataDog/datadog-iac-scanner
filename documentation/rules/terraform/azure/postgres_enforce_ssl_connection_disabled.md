---
title: "ssl_enforcement_enabled is not set to ENABLED for PostgreSQL database server"
group_id: "Terraform / Azure"
meta:
  name: "azure/postgres_enforce_ssl_connection_disabled"
  id: "93f9tyjk-e5f6-7890-ab12-cd34ef567890"
  display_name: "ssl_enforcement_enabled is not set to ENABLED for PostgreSQL database server"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `93f9tyjk-e5f6-7890-ab12-cd34ef567890`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server)

### Description

SSL/TLS encryption is essential for PostgreSQL Database Servers to protect sensitive data during transmission between the client and server. When `ssl_enforcement_enabled` is not set to `ENABLED`, data transferred between clients and the database is vulnerable to eavesdropping, man-in-the-middle attacks, and data tampering. This security vulnerability could lead to unauthorized access and data exposure.

Insecure configuration example:
```terraform
resource "azurerm_postgresql_server" "bad_example" {
  // ... other configuration
  ssl_enforcement_enabled = ["DISABLED"] // Insecure
}
```

Secure configuration example:
```terraform
resource "azurerm_postgresql_server" "good_example" {
  // ... other configuration
  ssl_enforcement_enabled = ["ENABLED"] // Secure setting
}
```

## Compliant Code Examples
```terraform
resource "azurerm_postgresql_server" "good_example" {
  name                = "good-postgresql-server"
  location            = "East US"
  resource_group_name = "example-rg"
  sku_name            = "B_Gen5_1"
  version             = "9.6"

  ssl_enforcement_enabled = ["ENABLED"] # ✅ Correct setting
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_postgresql_server" "bad_example" {
  name                = "bad-postgresql-server"
  location            = "East US"
  resource_group_name = "example-rg"
  sku_name            = "B_Gen5_1"
  version             = "9.6"

  ssl_enforcement_enabled = ["DISABLED"] # ❌ SSL enforcement is not enabled
}

```