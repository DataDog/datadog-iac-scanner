---
title: "SSO policy with full privileges"
group_id: "Terraform / AWS"
meta:
  name: "aws/sso_policy_with_full_privileges"
  id: "132a8c31-9837-4203-9fd1-15ca210c7b73"
  display_name: "SSO policy with full privileges"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `132a8c31-9837-4203-9fd1-15ca210c7b73`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssoadmin_permission_set_inline_policy)

### Description

Single Sign-On (SSO) policies should be configured to grant only the specific administrative privileges necessary, rather than granting unrestricted access to all AWS resources. If the inline policy uses broad permissions such as `"Action": ["*"]` and `"Resource": ["*"]`, as seen in the example below, it grants users full administrative rights, bypassing the principles of least privilege:

```
inline_policy = <<POLICY
{
  "Statement": [
    {
      "Action": [
        "*"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ],
      "Sid": ""
    }
  ],
  "Version": "2012-10-17"
}
POLICY
```

This misconfiguration exposes the environment to significant security risks, as any user assigned this policy could perform destructive actions or gain unauthorized access to sensitive data. Properly scoping permissions is crucial to minimize potential damage in the event of compromised credentials or malicious insiders. Failure to address this issue can lead to data breaches, accidental resource deletion, and loss of control over the cloud environment.

## Compliant Code Examples
```terraform
resource "aws_ssoadmin_permission_set_inline_policy" "neg1" {
  instance_arn       = aws_ssoadmin_permission_set.example.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.example.arn
  inline_policy = <<POLICY
{
  "Statement": [
    {
      "Action": [
        "s3:ListBucket*",
        "s3:HeadBucket",
        "s3:Get*"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::b1",
        "arn:aws:s3:::b1/*",
        "arn:aws:s3:::b2",
        "arn:aws:s3:::b2/*"
      ],
      "Sid": ""
    },
    {
      "Action": "s3:PutObject*",
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::b1/*",
      "Sid": ""
    }
  ],
  "Version": "2012-10-17"
}
POLICY
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_ssoadmin_permission_set_inline_policy" "pos1" {
  instance_arn       = aws_ssoadmin_permission_set.example.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.example.arn
  inline_policy = <<POLICY
{
  "Statement": [
    {
      "Action": [
        "*"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ],
      "Sid": ""
    },
    {
      "Action": "s3:PutObject*",
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::b1/*",
      "Sid": ""
    }
  ],
  "Version": "2012-10-17"
}
POLICY
}

```