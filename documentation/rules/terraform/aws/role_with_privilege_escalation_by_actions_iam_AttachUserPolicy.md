---
title: "Role with privilege escalation by actions 'iam:AttachUserPolicy'"
group_id: "Terraform / AWS"
meta:
  name: "aws/role_with_privilege_escalation_by_actions_iam_AttachUserPolicy"
  id: "7c96920c-6fd0-449d-9a52-0aa431b6beaf"
  display_name: "Role with privilege escalation by actions 'iam:AttachUserPolicy'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `7c96920c-6fd0-449d-9a52-0aa431b6beaf`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy#policy)

### Description

 Allowing an IAM role the action `iam:AttachUserPolicy` with a wildcard resource (`Resource = "*"`) grants broad privileges, enabling the role to attach any managed policy to any user in the AWS account. This constitutes a significant privilege escalation risk, as it allows users or roles with this permission to grant themselves or others additional permissions, potentially escalating to administrative access. To mitigate this risk, restrict the `Resource` attribute to specific ARNs and only grant necessary actions, as in the following secure example:

```
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
          "iam:AttachUserPolicy",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

```