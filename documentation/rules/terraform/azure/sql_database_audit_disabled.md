---
title: "SQL database audit disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/sql_database_audit_disabled"
  id: "83a229ba-483e-47c6-8db7-dc96969bce5a"
  display_name: "SQL database audit disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Resource Management"
---
## Metadata

**Id:** `83a229ba-483e-47c6-8db7-dc96969bce5a`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/3.6.0/docs/resources/sql_database)

### Description

 Enabling `Threat Detection` for Azure SQL Database helps identify anomalous activities and potential security threats by alerting administrators when suspicious activity is detected. If the threat_detection_policy block is set to `state = "Disabled"` or omitted entirely, as in the following configuration, threat detection will not be active: 

```
threat_detection_policy {
  state = "Disabled"
}
```

This increases the risk that unusual access patterns or potential SQL injection attacks go unnoticed, potentially leading to data breaches or data loss. To secure your deployment, configure the `threat_detection_policy` block as follows:

```
threat_detection_policy {
  state = "Enabled"
}
```
If left unaddressed, disabling this feature may allow attackers to exploit vulnerabilities in your database environment undetected.


## Compliant Code Examples
```terraform
resource "azurerm_resource_group" "negative1" {
  name     = "acceptanceTestResourceGroup1"
  location = "West US"
}

resource "azurerm_sql_server" "negative2" {
  name                         = "myexamplesqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = "West US"
  version                      = "12.0"
  administrator_login          = "4dm1n157r470r"
  administrator_login_password = "4-v3ry-53cr37-p455w0rd"

  tags = {
    environment = "production"
  }
}

resource "azurerm_storage_account" "negative3" {
  name                     = "examplesa"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_sql_database" "negative4" {
  name                = "myexamplesqldatabase"
  resource_group_name = azurerm_resource_group.example.name
  location            = "West US"
  server_name         = azurerm_sql_server.example.name

  threat_detection_policy {
    state = "Enabled"
  }

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 6
  }



  tags = {
    environment = "production"
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_resource_group" "positive1" {
  name     = "acceptanceTestResourceGroup1"
  location = "West US"
}

resource "azurerm_sql_server" "positive2" {
  name                         = "myexamplesqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = "West US"
  version                      = "12.0"
  administrator_login          = "4dm1n157r470r"
  administrator_login_password = "4-v3ry-53cr37-p455w0rd"

  tags = {
    environment = "production"
  }
}

resource "azurerm_storage_account" "positive3" {
  name                     = "examplesa"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_sql_database" "positive4" {
  name                = "myexamplesqldatabase"
  resource_group_name = azurerm_resource_group.example.name
  location            = "West US"
  server_name         = azurerm_sql_server.example.name

  threat_detection_policy {
    state = "Disabled"
  }

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 6
  }

  tags = {
    environment = "production"
  }
}


resource "azurerm_sql_database" "positive5" {
  name                = "myexamplesqldatabase"
  resource_group_name = azurerm_resource_group.example.name
  location            = "West US"
  server_name         = azurerm_sql_server.example.name

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 6
  }

  tags = {
    environment = "production"
  }
}
```