---
title: "Group with privilege escalation by actions 'iam:PutUserPolicy'"
group_id: "Terraform / AWS"
meta:
  name: "aws/group_with_privilege_escalation_by_actions_iam_PutUserPolicy"
  id: "60263b4a-6801-4587-911d-919c37ed733b"
  display_name: "Group with privilege escalation by actions 'iam:PutUserPolicy'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `60263b4a-6801-4587-911d-919c37ed733b`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy#policy)

### Description

Allowing the action `iam:PutUserPolicy` on the `Resource` set to `"*"` in an inline group policy grants members of that group the ability to attach arbitrary permissions to any IAM user in the AWS account. This privilege escalation vulnerability could allow an attacker or compromised group member to grant themselves administrative access, bypass intended access controls, or compromise the entire AWS environment. To mitigate this risk, restrict the `iam:PutUserPolicy` action to specific users or resources and avoid policies with wildcard resources where possible, as shown below in a secure example:

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
          "iam:PutUserPolicy",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}



```