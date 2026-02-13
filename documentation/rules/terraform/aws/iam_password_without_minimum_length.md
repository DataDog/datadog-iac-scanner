---
title: "IAM password without minimum length"
group_id: "Terraform / AWS"
meta:
  name: "aws/iam_password_without_minimum_length"
  id: "1bc1c685-e593-450e-88fb-19db4c82aa1d"
  display_name: "IAM password without minimum length"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `1bc1c685-e593-450e-88fb-19db4c82aa1d`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy)

### Description

 IAM password policies should enforce a minimum password length to ensure that user passwords are not easily guessable or vulnerable to brute-force attacks. If the `minimum_password_length` attribute is omitted or set to a low value, such as less than 14, users could create short and weak passwords that are more susceptible to compromise. Without this safeguard, unauthorized users could more easily gain access to sensitive cloud resources, increasing the risk of account takeover and data breaches. Enforcing a strong minimum password length is a critical security measure to help protect AWS accounts and resources from unauthorized access.


## Compliant Code Examples
```terraform
resource "aws_iam_account_password_policy" "negative1" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
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