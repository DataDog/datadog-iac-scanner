---
title: "Password without reuse prevention"
group_id: "Terraform / AWS"
meta:
  name: "aws/password_without_reuse_prevention"
  id: "89806cdc-9c2e-4bd1-a0dc-53f339bcfb2a"
  display_name: "Password without reuse prevention"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `89806cdc-9c2e-4bd1-a0dc-53f339bcfb2a`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy#password_reuse_prevention)

### Description

 This check ensures that the IAM account password policy's `password_reuse_prevention` attribute is set to at least 24, preventing users from reusing any of their last 24 passwords. Without this configuration, as seen when `password_reuse_prevention = 20` or when the attribute is omitted, users may repeatedly cycle through a small set of previously used passwords, increasing the risk of password-related attacks. Configuring a secure password policy, as in the following example, helps to enforce strong password hygiene and mitigates the likelihood of compromised credentials being reused:

```
resource "aws_iam_account_password_policy" "secure" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
}
```


## Compliant Code Examples
```terraform
resource "aws_iam_account_password_policy" "negative1" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention = 24
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_iam_account_password_policy" "positive1" {
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention = 20
}

resource "aws_iam_account_password_policy" "positive2" {
  minimum_password_length        = 3
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
}

```