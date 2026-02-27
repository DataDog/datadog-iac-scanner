---
title: "Role with privilege escalation by actions 'lambda:UpdateFunctionCode'"
group_id: "Terraform / AWS"
meta:
  name: "aws/role_with_privilege_escalation_by_actions_lambda_UpdateFunctionCode"
  id: "c583f0f9-7dfd-476b-a056-f47c62b47b46"
  display_name: "Role with privilege escalation by actions 'lambda:UpdateFunctionCode'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `c583f0f9-7dfd-476b-a056-f47c62b47b46`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy#policy)

### Description

Granting an IAM role permission for the `lambda:UpdateFunctionCode` action with a resource set to `"*"` allows the role to update the code of any Lambda function in the AWS account, opening the door for privilege escalation. An attacker with this permission could alter Lambda function code to obtain higher privileges or execute unauthorized actions, potentially compromising the security of the entire AWS environment. To mitigate this risk, restrict the `Resource` attribute to only the specific Lambda functions that need to be updated and avoid using the wildcard `"*"`.

A secure Terraform configuration should look like the following:

```
resource "aws_iam_role_policy" "secure_inline_policy" {
  name = "secure_inline_policy"
  role = aws_iam_role.cosmic.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "lambda:UpdateFunctionCode",
        ]
        Effect   = "Allow"
        Resource = "arn:aws:lambda:us-east-1:123456789012:function:specific-function"
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
          "lambda:UpdateFunctionCode",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}



```