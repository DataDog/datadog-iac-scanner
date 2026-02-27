---
title: "RAM account password policy without reuse prevention"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ram_account_password_policy_without_reuse_prevention"
  id: "a8128dd2-89b0-464b-98e9-5d629041dfe0"
  display_name: "RAM account password policy without reuse prevention"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `a8128dd2-89b0-464b-98e9-5d629041dfe0`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_account_password_policy#password_reuse_prevention)

### Description

The RAM account password policy attribute `password_reuse_prevention` should be defined and set to `24` or less. If `password_reuse_prevention` is missing, the rule reports a `MissingAttribute` issue and recommends adding `password_reuse_prevention = 24`. If it is present but set to a value greater than `24`, the rule reports an `IncorrectValue` issue and recommends replacing it with `24`.

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
  max_password_age             = 12
  password_reuse_prevention    = 25
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
  max_login_attempts           = 3
}

```