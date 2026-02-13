---
title: "Role with privilege escalation by actions 'iam:AddUserToGroup'"
group_id: "Terraform / AWS"
meta:
  name: "aws/role_with_privilege_escalation_by_actions_iam_AddUserToGroup"
  id: "b8a31292-509d-4b61-bc40-13b167db7e9c"
  display_name: "Role with privilege escalation by actions 'iam:AddUserToGroup'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `b8a31292-509d-4b61-bc40-13b167db7e9c`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy#policy)

### Description

Granting the `iam:AddUserToGroup` action with a `Resource` value of `"*"` in an IAM role, such as in the example below, allows any user or role assigned this policy to add themselves or any user to any IAM group in the account.

```
resource "aws_iam_role_policy" "test_inline_policy" {
  ...
  policy = jsonencode({
    ...
    Statement = [
      {
        Action = [
          "iam:AddUserToGroup",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}
```

This configuration creates a privilege escalation risk, as users may gain unauthorized permissions by adding themselves to groups with higher privileges, potentially leading to account compromise. Limiting both the allowed action and narrowing the resources by specifying particular group ARNs greatly reduces this attack surface.

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
          "iam:AddUserToGroup",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


```