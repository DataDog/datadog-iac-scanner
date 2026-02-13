---
title: "Group with privilege escalation by actions 'glue:CreateDevEndpoint' and 'iam:PassRole'"
group_id: "Terraform / AWS"
meta:
  name: "aws/group_with_privilege_escalation_by_actions_iam_PassRole_and_glue_CreateDevEndpoint"
  id: "7d544dad-8a6c-431c-84c1-5f07fe9afc0e"
  display_name: "Group with privilege escalation by actions 'glue:CreateDevEndpoint' and 'iam:PassRole'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `7d544dad-8a6c-431c-84c1-5f07fe9afc0e`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy#policy)

### Description

Granting an IAM group the permissions `glue:CreateDevEndpoint` and `iam:PassRole` with the `Resource` field set to `*` creates a significant privilege escalation risk. With these permissions, a user can create an AWS Glue Development Endpoint while passing any IAM role of their choosing, effectively allowing them to assume roles with higher privileges than originally authorized. If this misconfiguration is left unaddressed, attackers or unprivileged users could leverage this pathway to gain full administrative access over the AWS environment, bypassing the intended separation of duties. To minimize this risk, always restrict the `Resource` field to specific, intended roles and endpoints, and avoid using `"Resource": "*"` in sensitive IAM policy configurations.

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
resource "aws_iam_group" "cosmic" {
  name = "cosmic"
}

resource "aws_iam_group_policy" "test_inline_policy" {
  name = "test_inline_policy"
  group = aws_iam_group.cosmic.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "glue:CreateDevEndpoint",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


resource "aws_iam_policy_attachment" "test-attach" {
  name       = "test-attachment"
  groups     = [aws_iam_group.cosmic.name]
  policy_arn = aws_iam_policy.policy.arn
}


resource "aws_iam_policy" "policy" {
  name        = "test-policy"
  description = "A test policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "iam:PassRole",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

```