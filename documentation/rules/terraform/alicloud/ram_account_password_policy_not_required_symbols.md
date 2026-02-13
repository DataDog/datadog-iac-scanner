---
title: "RAM account password policy does not require symbols"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ram_account_password_policy_not_required_symbols"
  id: "41a38329-d81b-4be4-aef4-55b2615d3282"
  display_name: "RAM account password policy does not require symbols"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Secret Management"
---
## Metadata

**Id:** `41a38329-d81b-4be4-aef4-55b2615d3282`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Low

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy#require_symbols)

### Description

RAM account password security should require at least one symbol.
Specifically, the `alicloud_ram_account_password_policy` resource must have the `require_symbols` attribute set to `true`.
This rule flags cases where `require_symbols` is `false` as an `IncorrectValue` issue and suggests replacing it with `true`.

## Compliant Code Examples
```terraform
resource "alicloud_ram_account_password_policy" "corporate1" {
  minimum_password_length      = 9
  require_lowercase_characters = false
  require_uppercase_characters = false
  require_numbers              = false
  require_symbols              = true
  hard_expiry                  = true
  max_password_age             = 12
  password_reuse_prevention    = 5
  max_login_attempts           = 3
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_ram_account_password_policy" "corporate2" {
  minimum_password_length      = 9
  require_lowercase_characters = false
  require_uppercase_characters = false
  require_numbers              = false
  require_symbols              = false
  hard_expiry                  = true
  max_password_age             = 12
  password_reuse_prevention    = 5
  max_login_attempts           = 3
}

```