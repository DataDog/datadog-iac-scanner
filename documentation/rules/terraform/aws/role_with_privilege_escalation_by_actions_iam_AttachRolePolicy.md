---
title: "Role with privilege escalation by actions 'iam:AttachRolePolicy'"
group_id: "Terraform / AWS"
meta:
  name: "aws/role_with_privilege_escalation_by_actions_iam_AttachRolePolicy"
  id: "f465fff1-0a0f-457d-aa4d-1bddb6f204ff"
  display_name: "Role with privilege escalation by actions 'iam:AttachRolePolicy'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `f465fff1-0a0f-457d-aa4d-1bddb6f204ff`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy#policy)

### Description

Granting an IAM role permission to perform `iam:AttachRolePolicy` with `Resource = "*"` allows the role to attach any policy to any role in the AWS environment, including itself. This enables privilege escalation, as a user or process with this permission can grant themselves full administrative privileges or access beyond what was originally intended. If left unaddressed, such a configuration could lead to unauthorized access, data breaches, or full compromise of the AWS account.

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
          "iam:AttachRolePolicy",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

```