---
title: "Role with privilege escalation by actions 'iam:UpdateAssumeRolePolicy' and 'sts:AssumeRole'"
group_id: "Terraform / AWS"
meta:
  name: "aws/role_with_privilege_escalation_by_actions_iam_UpdateAssumeRolePolicy_and_sts_AssumeRole"
  id: "f1173d8c-3264-4148-9fdb-61181e031b51"
  display_name: "Role with privilege escalation by actions 'iam:UpdateAssumeRolePolicy' and 'sts:AssumeRole'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `f1173d8c-3264-4148-9fdb-61181e031b51`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy#policy)

### Description

 Granting an IAM role permissions for both `iam:UpdateAssumeRolePolicy` and `sts:AssumeRole` actions with the `Resource` attribute set to `"*"` creates a severe privilege escalation risk. This misconfiguration allows a user or role to modify the trust policies of any role and subsequently assume any role in the AWS account, potentially gaining administrative privileges. If left unaddressed, malicious actors could exploit these permissions to take over sensitive roles and perform unauthorized actions across all AWS resources.


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
          "iam:UpdateAssumeRolePolicy",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


resource "aws_iam_policy_attachment" "test-attach" {
  name       = "test-attachment"
  roles      = [aws_iam_role.cosmic.name]
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
          "sts:AssumeRole",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

```