---
title: "Geo redundancy is disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/geo_redundancy_is_disabled"
  id: "8b042c30-e441-453f-b162-7696982ebc58"
  display_name: "Geo redundancy is disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Backup"
---
## Metadata

**Id:** `8b042c30-e441-453f-b162-7696982ebc58`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Backup

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server)

### Description

Geo-redundant backups should be enabled on Azure PostgreSQL servers to ensure critical data is protected and recoverable even if a regional outage occurs. The `geo_redundant_backup_enabled` attribute should be set to `true` for high availability; otherwise, setting it to `false` can leave backups vulnerable to loss in disaster recovery scenarios. For example, a secure configuration would look like the following:

```
resource "azurerm_postgresql_server" "example" {
    name                = "dbserver"
    location            = "usgovvirginia"
    resource_group_name = azurerm_resource_group.jira_rg.name

    sku_name   = "GP_Gen5_4"
    version    = "9.6"
    storage_mb = 640000

    backup_retention_days        = var.jira_postgre_data_retention
    geo_redundant_backup_enabled = true
    auto_grow_enabled            = true

    administrator_login          = var.mp_db_username
    administrator_login_password = azurerm_key_vault_secret.db_pswd.value
    ssl_enforcement_enabled      = true

    tags                         = local.postgresqlserver_tags
}
```
Without geo-redundant backups enabled, business-critical data may become unrecoverable if the primary region experiences a catastrophic failure, risking significant data loss and service disruption.

## Compliant Code Examples
```terraform
resource "azurerm_postgresql_server" "negative1" {
    name                = "dbserver"
    location            = "usgovvirginia"
    resource_group_name = azurerm_resource_group.jira_rg.name

    sku_name   = "GP_Gen5_4"
    version    = "9.6"
    storage_mb = 640000

    backup_retention_days        = var.jira_postgre_data_retention
    geo_redundant_backup_enabled = true
    auto_grow_enabled            = true

    administrator_login          = var.mp_db_username
    administrator_login_password = azurerm_key_vault_secret.db_pswd.value
    ssl_enforcement_enabled      = false

    tags                         = local.postgresqlserver_tags
}

```
## Non-Compliant Code Examples
```terraform

resource "azurerm_postgresql_server" "positive1" {
    name                = "dbserver"
    location            = "usgovvirginia"
    resource_group_name = azurerm_resource_group.jira_rg.name

    sku_name   = "GP_Gen5_4"
    version    = "9.6"
    storage_mb = 640000

    backup_retention_days        = var.jira_postgre_data_retention
    auto_grow_enabled            = true

    administrator_login          = var.mp_db_username
    administrator_login_password = azurerm_key_vault_secret.db_pswd.value
    ssl_enforcement_enabled      = true

    tags                         = local.postgresqlserver_tags
}

resource "azurerm_postgresql_server" "positive2" {
    name                = "dbserver"
    location            = "usgovvirginia"
    resource_group_name = azurerm_resource_group.jira_rg.name

    sku_name   = "GP_Gen5_4"
    version    = "9.6"
    storage_mb = 640000

    backup_retention_days        = var.jira_postgre_data_retention
    geo_redundant_backup_enabled = false
    auto_grow_enabled            = true

    administrator_login          = var.mp_db_username
    administrator_login_password = azurerm_key_vault_secret.db_pswd.value
    ssl_enforcement_enabled      = false

    tags                         = local.postgresqlserver_tags
}

```