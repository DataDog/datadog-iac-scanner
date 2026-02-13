---
title: "IAM password policy does not require numbers"
group_id: "Terraform / AWS"
meta:
  name: "aws/iam_password_does_not_require_number"
  id: "bts2c3d4-e5f6-7890-ab12-cd34ef567890"
  display_name: "IAM password policy does not require numbers"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `bts2c3d4-e5f6-7890-ab12-cd34ef567890`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy#require_symbols)

### Description

 This check ensures that the AWS IAM account password policy enforces the use of at least one number in user passwords by verifying that the `require_number` attribute is set to `true` in the `aws_iam_account_password_policy` resource. If this setting is not enabled, as shown in the configuration `require_number = false`, users may set simple passwords that lack special characters, making them easier for attackers to guess or crack using brute-force techniques.

Passwords without numbers significantly reduce the complexity and entropy of user credentials, increasing the risk of unauthorized access to AWS accounts and resources. Enforcing passwords with numbers enhances overall account security by making passwords more resistant to common password attacks. If this configuration is left unaddressed, the AWS environment may be exposed to increased risk of compromise due to weak password practices.


## Compliant Code Examples
```terraform
resource "aws_iam_account_password_policy" "good_example" {
  minimum_password_length      = 14
  require_symbols              = true
  require_numbers              = true
  require_lowercase_characters = true
  require_uppercase_characters = true
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_iam_account_password_policy" "bad_example" {
  minimum_password_length      = 14
  require_symbols              = true
  require_numbers              = false
  require_lowercase_characters = true
  require_uppercase_characters = true
}

```