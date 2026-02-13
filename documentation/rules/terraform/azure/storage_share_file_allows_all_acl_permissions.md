---
title: "Storage share file allows all ACL permissions"
group_id: "Terraform / Azure"
meta:
  name: "azure/storage_share_file_allows_all_acl_permissions"
  id: "48bbe0fd-57e4-4678-a4a1-119e79c90fc3"
  display_name: "Storage share file allows all ACL permissions"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `48bbe0fd-57e4-4678-a4a1-119e79c90fc3`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_share_file)

### Description

 Allowing all Access Control List (ACL) permissions(`rwdl` for read, write, delete, and list) on an Azure storage file share grants overly broad access, increasing the risk of unauthorized access, data leakage, or malicious data manipulation. This misconfiguration could allow any user or process with the relevant access policy to not only read and list files, but also modify or delete important data, potentially leading to service disruption or data loss. To mitigate this risk, permissions should be set according to the principle of least privilege, For example, grant only `r` (read) permissions when read-only access is required, as shown below:

```
resource "azurerm_storage_share" "example" {
  name                 = "sharename"
  storage_account_name = "mystorageaccount"
  quota                = 50

  acl {
    id = "unique-acl-id"

    access_policy {
      permissions = "r"
      start       = "2024-06-07T09:38:21.0000000Z"
      expiry      = "2025-06-07T09:38:21.0000000Z"
    }
  }
}

resource "azurerm_storage_share_file" "example" {
  name             = "read-only-file.zip"
  storage_share_id = azurerm_storage_share.example.id
  source           = "some-local-file.zip"
}
```


## Compliant Code Examples
```terraform
resource "azurerm_storage_table" "table_resource2" {
  name                 = "my_table_name"
  storage_account_name = "mystoragexxx"
  acl {
    id = "someid-1XXXXXXXXX"
    access_policy {
      expiry = "2022-10-03T05:05:00.0000000Z"
      permissions = "r"
      start = "2021-05-28T04:05:00.0000000Z"
    }
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_storage_share" "example" {
  name                 = "sharename"
  storage_account_name = azurerm_storage_account.example.name
  quota                = 50

  acl {
    id = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI"

    access_policy {
      permissions = "rwdl"
      start       = "2022-07-02T09:38:21.0000000Z"
      expiry      = "2021-07-02T10:38:21.0000000Z"
    }
  }
}

resource "azurerm_storage_share_file" "example" {
  name             = "my-awesome-content.zip"
  storage_share_id = azurerm_storage_share.example.id
  source           = "some-local-file.zip"
}

```