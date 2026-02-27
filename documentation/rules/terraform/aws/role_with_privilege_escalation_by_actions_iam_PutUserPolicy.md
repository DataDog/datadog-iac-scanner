---
title: "Role with privilege escalation by actions 'iam:PutUserPolicy'"
group_id: "Terraform / AWS"
meta:
  name: "aws/role_with_privilege_escalation_by_actions_iam_PutUserPolicy"
  id: "8f75840d-9ee7-42f3-b203-b40e3979eb12"
  display_name: "Role with privilege escalation by actions 'iam:PutUserPolicy'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `8f75840d-9ee7-42f3-b203-b40e3979eb12`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy#policy)

### Description

Allowing the `iam:PutUserPolicy` action with a `Resource` value of `"*"` in a Terraform AWS IAM role or policy configuration allows any user assigned the role to attach arbitrary policies to any users in the AWS account. This creates a significant privilege escalation vulnerability, as an attacker could grant themselves or others increased permissions, potentially leading to full administrative access. To mitigate this risk, the scope of the `PutUserPolicy` action should be strictly restricted to only the necessary resources and users.

## Compliant Code Examples
```terraform
resource "aws_iam_user" "cosmic2" {
  name = "cosmic2"
}

resource "aws_iam_user_policy" "inline_policy_run_instances2" {
  name = "inline_policy_run_instances"
  user = aws_iam_user.cosmic2.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_iam_role" "cosmic" {
  name = "cosmic"
}

resource "aws_iam_role_policy" "test_inline_policy" {
  name = "test_inline_policy"
  role = aws_iam_role.cosmic.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "iam:PutUserPolicy",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


```