---
title: "RAM account password policy does not enforce minimum password length"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ram_account_password_policy_not_required_minimum_length"
  id: "a9dfec39-a740-4105-bbd6-721ba163c053"
  display_name: "RAM account password policy does not enforce minimum password length"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Secret Management"
---
## Metadata

**Id:** `a9dfec39-a740-4105-bbd6-721ba163c053`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Low

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy#minimum_password_length)

### Description

The RAM account password policy must define `minimum_password_length` and set it to `14` or greater. If the attribute is missing, the policy is non-compliant and should include `minimum_password_length = 14`. This rule reports `IncorrectValue` when the attribute is defined but below `14`, and `MissingAttribute` when it is not defined.

## Compliant Code Examples
```terraform
resource "alicloud_ram_account_password_policy" "corporate" {
  minimum_password_length      = 14
  require_lowercase_characters = false
  require_uppercase_characters = false
  require_numbers              = false
  require_symbols              = false
  hard_expiry                  = true
  max_password_age             = 14
  password_reuse_prevention    = 5
  max_login_attempts           = 3
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_ram_account_password_policy" "corporate" {
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

```terraform
resource "alicloud_ram_account_password_policy" "corporate" {
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