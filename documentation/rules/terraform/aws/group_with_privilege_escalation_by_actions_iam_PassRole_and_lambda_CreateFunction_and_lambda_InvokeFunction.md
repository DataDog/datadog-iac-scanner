---
title: "Group with privilege escalation by actions 'lambda:CreateFunction' and 'iam:PassRole' and 'lambda:InvokeFunction'"
group_id: "Terraform / AWS"
meta:
  name: "aws/group_with_privilege_escalation_by_actions_iam_PassRole_and_lambda_CreateFunction_and_lambda_InvokeFunction"
  id: "034d0aee-620f-4bf7-b7fb-efdf661fdb9e"
  display_name: "Group with privilege escalation by actions 'lambda:CreateFunction' and 'iam:PassRole' and 'lambda:InvokeFunction'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `034d0aee-620f-4bf7-b7fb-efdf661fdb9e`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy#policy)

### Description

This configuration allows an IAM group to escalate privileges by combining `lambda:CreateFunction`, `iam:PassRole`, and `lambda:InvokeFunction` permissions, all with the overly broad `Resource = "*"`. Attackers or unauthorized users with this access can create, invoke, and assign any role to Lambda functions, potentially gaining permissions beyond their intended scope and compromising the entire AWS account. To prevent this, restrict `iam:PassRole` and Lambda actions to specific, necessary resources and ensure that the policy does not broadly grant privileges, as shown below:

```
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
          "lambda:CreateFunction",
          "lambda:InvokeFunction"
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