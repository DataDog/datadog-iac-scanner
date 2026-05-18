---
title: "IAM password policy does not require lowercase letter"
group_id: "Terraform / AWS"
meta:
  name: "aws/iam_password_does_not_require_lowercase"
  id: "terraform-aws-iam-password-does-not-require-lowercase"
  display_name: "IAM password policy does not require lowercase letter"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-aws-iam-password-does-not-require-lowercase{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy#require_lowercase_characters)

### Description

This check ensures that the AWS IAM password policy enforces the use of at least one lowercase letter in user passwords by setting `require_lowercase_characters = true` in the `aws_iam_account_password_policy` resource. If this setting is left as `require_lowercase_characters = false`, passwords are less complex and easier for attackers to guess or brute-force, increasing the risk of unauthorized access to AWS resources. Weak password policies can significantly undermine the security posture of your AWS environment.

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
  require_numbers              = true
  require_lowercase_characters = false
  require_uppercase_characters = true
}

```