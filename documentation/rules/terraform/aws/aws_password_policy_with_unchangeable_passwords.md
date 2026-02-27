---
title: "AWS password policy with unchangeable passwords"
group_id: "Terraform / AWS"
meta:
  name: "aws/aws_password_policy_with_unchangeable_passwords"
  id: "9ef7d25d-9764-4224-9968-fa321c56ef76"
  display_name: "AWS password policy with unchangeable passwords"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `9ef7d25d-9764-4224-9968-fa321c56ef76`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy)

### Description

This check evaluates whether the AWS IAM account password policy allows users to change their own passwords by ensuring the attribute `allow_users_to_change_password` is set to `true`. If `allow_users_to_change_password` is set to `false`, users are prevented from updating their passwords, which can lead to stale or compromised credentials remaining in active use. This increases the risk of unauthorized account access, as users are unable to maintain password hygiene or respond quickly to potential credential exposures.

## Compliant Code Examples
```terraform
resource "aws_sqs_queue" "negative1" {
  name = "examplequeue"
}

// comment
resource "aws_iam_account_password_policy" "negative2" {
  minimum_password_length        = 10
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_sqs_queue" "positive1" {
  name = "examplequeue"
}

// comment
resource "aws_iam_account_password_policy" "positive2" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = false
}
```