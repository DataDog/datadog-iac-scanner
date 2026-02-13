---
title: "Group with privilege escalation by actions 'lambda:UpdateFunctionCode'"
group_id: "Terraform / AWS"
meta:
  name: "aws/group_with_privilege_escalation_by_actions_lambda_UpdateFunctionCode"
  id: "571254d8-aa6a-432e-9725-535d3ef04d69"
  display_name: "Group with privilege escalation by actions 'lambda:UpdateFunctionCode'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `571254d8-aa6a-432e-9725-535d3ef04d69`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy#policy)

### Description

 Granting the `lambda:UpdateFunctionCode` permission with the `Resource` attribute set to `"*"` in an IAM group policy enables users in that group to update the code of any Lambda function within the AWS account. This broad permission could allow a user to inject malicious code into critical Lambda functions or leverage those functions for privilege escalation, compromising the overall security of the environment. To mitigate this risk, permissions should be limited to only trusted users and to specific, necessary Lambda functions using fine-grained resource ARNs rather than wildcard resources.


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
          "lambda:UpdateFunctionCode",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

```