---
title: "User with privilege escalation by actions 'iam:AttachUserPolicy'"
group_id: "Terraform / AWS"
meta:
  name: "aws/user_with_privilege_escalation_by_actions_iam_AttachUserPolicy"
  id: "70cb518c-d990-46f6-bc05-44a5041493d6"
  display_name: "User with privilege escalation by actions 'iam:AttachUserPolicy'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `70cb518c-d990-46f6-bc05-44a5041493d6`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_user_policy#policy)

### Description

 This check identifies IAM policies that permit the action `iam:AttachUserPolicy` with the `Resource` field set to `"*"`. Granting this permission to a user, as shown below, allows them to attach any AWS managed or custom policy to any user, which can lead to privilege escalation and potential compromise of the AWS environment.

```
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
```

If left unaddressed, an attacker with this permission could escalate their privileges far beyond what was originally intended, potentially gaining administrative access and leading to a full environment takeover.


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
resource "aws_iam_user" "cosmic" {
  name = "cosmic"
}

resource "aws_iam_user_policy" "test_inline_policy" {
  name = "test_inline_policy"
  user = aws_iam_user.cosmic.name

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


resource "aws_iam_policy_attachment" "test-attach" {
  name       = "test-attachment"
  users      = [aws_iam_user.cosmic.name]
  roles      = [aws_iam_role.role.name]
  groups     = [aws_iam_group.group.name]
}

```