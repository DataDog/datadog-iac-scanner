---
title: "RAM account password policy max login attempts not recommended"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ram_account_password_policy_max_login_attempts_unrecommended"
  id: "e76fd7ab-7333-40c6-a2d8-ea28af4a319e"
  display_name: "RAM account password policy max login attempts not recommended"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `e76fd7ab-7333-40c6-a2d8-ea28af4a319e`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy#max_login_attempts)

### Description

The RAM account password policy must limit `max_login_attempts` to a maximum of `5` incorrect login attempts. This rule flags any `alicloud_ram_account_password_policy` resource where `max_login_attempts` exceeds `5`. To enforce the limit, set `max_login_attempts = 5`.

## Compliant Code Examples
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
  max_login_attempts           = 6
}

```