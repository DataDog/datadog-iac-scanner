---
title: "Storage account not using latest TLS encryption version"
group_id: "Terraform / Azure"
meta:
  name: "azure/storage_account_not_using_latest_tls_encryption_version"
  id: "8263f146-5e03-43e0-9cfe-db960d56d1e7"
  display_name: "Storage account not using latest TLS encryption version"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `8263f146-5e03-43e0-9cfe-db960d56d1e7`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account)

### Description

To ensure data transmitted to and from Azure storage accounts remains protected, it is important to enforce the use of the latest supported TLS encryption protocol. If the `min_tls_version` attribute is set to an outdated protocol such as `"TLS1_1"`, as seen below, the storage account may be vulnerable to known security exploits:

```
  min_tls_version = "TLS1_1"
```

To mitigate this risk, configure storage accounts to use at least TLS 1.2 by setting:

```
  min_tls_version = "TLS1_2"
```

Failing to enforce modern TLS versions can expose sensitive data in transit to interception or tampering by attackers.

## Compliant Code Examples
```terraform
resource "azurerm_storage_account" "negative1" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version = "TLS1_2"

  tags = {
    environment = "staging"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_storage_account" "positive2" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version = "TLS1_1"

  tags = {
    environment = "staging"
  }
}

```