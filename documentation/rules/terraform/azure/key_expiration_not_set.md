---
title: "Key expiration not set"
group_id: "Terraform / Azure"
meta:
  name: "azure/key_expiration_not_set"
  id: "4d080822-5ee2-49a4-8984-68f3d4c890fc"
  display_name: "Key expiration not set"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `4d080822-5ee2-49a4-8984-68f3d4c890fc`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key)

### Description

To ensure cryptographic hygiene and limit risk exposure, all keys managed by Azure Key Vault should have an explicit expiration date set using the `expiration_date` attribute. Without an expiration, keys may remain valid indefinitely, increasing the likelihood of unauthorized access or misuse if the key is ever compromised. For example, a secure configuration includes `expiration_date`, as shown below:

```
resource "azurerm_key_vault_key" "example" {
  name             = "generated-certificate"
  key_vault_id     = azurerm_key_vault.example.id
  key_type         = "RSA"
  key_size         = 2048
  key_opts         = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
  expiration_date  = "2020-12-30T20:00:00Z"
}
```

Failure to set this attribute can result in persistent, potentially stale keys that remain active past their intended lifecycle, increasing the attack surface.

## Compliant Code Examples
```terraform
resource "azurerm_key_vault_key" "negative1" {
    name         = "generated-certificate"
    key_vault_id = azurerm_key_vault.example.id
    key_type     = "RSA"
    key_size     = 2048

    key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
    ]
  expiration_date = "2020-12-30T20:00:00Z"
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_key_vault_key" "positive1" {
    name         = "generated-certificate"
    key_vault_id = azurerm_key_vault.example.id
    key_type     = "RSA"
    key_size     = 2048

    key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
    ]
}
```