---
title: "RAM account password policy not require at least one lowercase character"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ram_password_security_policy_not_require_at_least_one_lowercase_character"
  id: "terraform-alicloud-ram-password-security-policy-not-require-at-least-one-lowercase-character"
  display_name: "RAM account password policy not require at least one lowercase character"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Secret Management"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-alicloud-ram-password-security-policy-not-require-at-least-one-lowercase-character{{< /copyable-code >}}

**Provider:** Alicloud

**Platform:** Terraform

**Severity:** Low

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy#require_lowercase_characters)

### Description

The RAM account password policy (`alicloud_ram_account_password_policy`) must set `require_lowercase_characters` to `true`. This ensures that account passwords include at least one lowercase character to meet complexity requirements. Resources with `require_lowercase_characters` set to `false` are non-compliant and should be updated to `true`.

## Compliant Code Examples
```terraform
resource "alicloud_ram_account_password_policy" "corporate" {
  minimum_password_length      = 9
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
  require_lowercase_characters = true
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
  max_login_attempts           = 3
}

```