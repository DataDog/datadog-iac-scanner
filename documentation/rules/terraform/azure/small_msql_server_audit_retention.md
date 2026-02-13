---
title: "Small MSSQL server audit retention"
group_id: "Terraform / Azure"
meta:
  name: "azure/small_msql_server_audit_retention"
  id: "59acb56b-2b10-4c2c-ba38-f2223c3f5cfc"
  display_name: "Small MSSQL server audit retention"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `59acb56b-2b10-4c2c-ba38-f2223c3f5cfc`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server)

### Description

SQL Server auditing logs should be retained for more than 90 days to ensure sufficient historical data is available for security investigations and compliance requirements. When the `retention_in_days` attribute in the `extended_auditing_policy` block is set below 91, such as in the following Terraform snippet, essential audit records may be lost due to premature log deletion:

```
extended_auditing_policy {
  storage_endpoint            = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key  = azurerm_storage_account.example.primary_access_key
  retention_in_days           = 20
}
```

A secure configuration should set `retention_in_days` to at least 91, as shown below, to ensure audit logs are preserved for sufficient time:

```
extended_auditing_policy {
  storage_endpoint            = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key  = azurerm_storage_account.example.primary_access_key
  retention_in_days           = 91
}
```

Failing to enforce adequate audit log retention can prevent detection of security incidents and undermine compliance with regulatory standards.

## Compliant Code Examples
```terraform
resource "azurerm_sql_database" "negative1" {
  name                = "myexamplesqldatabase"
  resource_group_name = azurerm_resource_group.example.name
  location            = "West US"
  server_name         = azurerm_sql_server.example.name

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 91
  }

  tags = {
    environment = "production"
  }
}

resource "azurerm_sql_database" "negative2" {
  name                = "myexamplesqldatabase"
  resource_group_name = azurerm_resource_group.example.name
  location            = "West US"
  server_name         = azurerm_sql_server.example.name

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 214
  }

  tags = {
    environment = "production"
  }
}

resource "azurerm_sql_database" "negative3" {
  name                = "myexamplesqldatabase"
  resource_group_name = azurerm_resource_group.example.name
  location            = "West US"
  server_name         = azurerm_sql_server.example.name

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 30000
  }

  tags = {
    environment = "production"
  }
}

resource "azurerm_sql_database" "negative4" {
  name                = "myexamplesqldatabase"
  resource_group_name = azurerm_resource_group.example.name
  location            = "West US"
  server_name         = azurerm_sql_server.example.name

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 900
  }

  tags = {
    environment = "production"
  }
}

resource "azurerm_sql_server" "negative5" {
    name                         = "sqlserver"
    resource_group_name          = azurerm_resource_group.example.name
    location                     = azurerm_resource_group.example.location
    version                      = "12.0"
    administrator_login          = "mradministrator"
    administrator_login_password = "thisIsDog11"

    extended_auditing_policy {
      storage_endpoint            = azurerm_storage_account.example.primary_blob_endpoint
      storage_account_access_key  = azurerm_storage_account.example.primary_access_key
      storage_account_access_key_is_secondary = true
      retention_in_days                       = 95
    }
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_sql_database" "positive1" {
  name                = "myexamplesqldatabase"
  resource_group_name = azurerm_resource_group.example.name
  location            = "West US"
  server_name         = azurerm_sql_server.example.name

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
  }

  tags = {
    environment = "production"
  }
}

resource "azurerm_sql_database" "positive2" {
  name                = "myexamplesqldatabase"
  resource_group_name = azurerm_resource_group.example.name
  location            = "West US"
  server_name         = azurerm_sql_server.example.name

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 90
  }

  tags = {
    environment = "production"
  }
}

resource "azurerm_sql_database" "positive3" {
  name                = "myexamplesqldatabase"
  resource_group_name = azurerm_resource_group.example.name
  location            = "West US"
  server_name         = azurerm_sql_server.example.name

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 0
  }

  tags = {
    environment = "production"
  }
}

resource "azurerm_sql_server" "positive4" {
    name                         = "sqlserver"
    resource_group_name          = azurerm_resource_group.example.name
    location                     = azurerm_resource_group.example.location
    version                      = "12.0"
    administrator_login          = "mradministrator"
    administrator_login_password = "thisIsDog11"

    extended_auditing_policy {
      storage_endpoint            = azurerm_storage_account.example.primary_blob_endpoint
      storage_account_access_key  = azurerm_storage_account.example.primary_access_key
      storage_account_access_key_is_secondary = true
      retention_in_days                       = 20
    }
}

```