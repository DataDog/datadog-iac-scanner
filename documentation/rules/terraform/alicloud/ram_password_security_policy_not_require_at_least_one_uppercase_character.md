---
title: "RAM account password policy not require at least one uppercase character"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ram_password_security_policy_not_require_at_least_one_uppercase_character"
  id: "5e0fb613-ba9b-44c3-88f0-b44188466bfd"
  display_name: "RAM account password policy not require at least one uppercase character"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Secret Management"
---
## Metadata

**Id:** `5e0fb613-ba9b-44c3-88f0-b44188466bfd`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Low

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy#require_uppercase_characters)

### Description

The RAM account password policy attribute `require_uppercase_characters` should be set to `true`. If set to `false`, passwords may not require uppercase letters, weakening password complexity and increasing risk. Ensure the `alicloud_ram_account_password_policy` resource defines `require_uppercase_characters` as `true`.

## Compliant Code Examples
```terraform
resource "alicloud_ram_account_password_policy" "corporate" {
  minimum_password_length      = 9
  require_lowercase_characters = false
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
  require_uppercase_characters = true
  require_numbers              = false
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