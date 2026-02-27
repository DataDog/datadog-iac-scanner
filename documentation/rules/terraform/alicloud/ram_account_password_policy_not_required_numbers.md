---
title: "RAM account password policy does not require numbers"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ram_account_password_policy_not_required_numbers"
  id: "063234c0-91c0-4ab5-bbd0-47ddb5f23786"
  display_name: "RAM account password policy does not require numbers"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Secret Management"
---
## Metadata

**Id:** `063234c0-91c0-4ab5-bbd0-47ddb5f23786`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Low

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy#require_numbers)

### Description

The RAM account password policy resource `alicloud_ram_account_password_policy` should set `require_numbers` to `true`. This enforces the inclusion of numeric characters in passwords and strengthens account security. Resources where `require_numbers` is `false` or omitted will trigger this rule and should set `require_numbers = true`.

## Compliant Code Examples
```terraform
resource "alicloud_ram_account_password_policy" "corporate" {
  minimum_password_length      = 9
  require_lowercase_characters = false
  require_uppercase_characters = false
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
  require_numbers              = true
  require_symbols              = false
  hard_expiry                  = true
  max_password_age             = 12
  password_reuse_prevention    = 5
  max_login_attempts           = 3
}

```
## Non-Compliant Code Examples
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