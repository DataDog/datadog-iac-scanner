---
title: "RAM account password policy max password age not recommended"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ram_account_password_policy_max_password_age_unrecommended"
  id: "terraform-alicloud-ram-account-password-policy-max-password-age-unrecommended"
  display_name: "RAM account password policy max password age not recommended"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-alicloud-ram-account-password-policy-max-password-age-unrecommended{{< /copyable-code >}}

**Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy#max_password_age)

### Description

The `alicloud_ram_account_password_policy` attribute `max_password_age` must be greater than `0` and less than `91`. A missing `max_password_age`, a value of `0`, or any value greater than `90` is noncompliant. Recommended remediation: set `max_password_age` to `12`.

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
  max_password_age             = 92
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
  max_password_age             = 0
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
  password_reuse_prevention    = 5
  max_login_attempts           = 3
}

```