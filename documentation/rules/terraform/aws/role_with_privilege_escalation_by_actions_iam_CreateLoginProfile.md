---
title: "Role with privilege escalation by actions 'iam:CreateLoginProfile'"
group_id: "Terraform / AWS"
meta:
  name: "aws/role_with_privilege_escalation_by_actions_iam_CreateLoginProfile"
  id: "9a205ba3-0dd1-42eb-8d54-2ffec836b51a"
  display_name: "Role with privilege escalation by actions 'iam:CreateLoginProfile'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `9a205ba3-0dd1-42eb-8d54-2ffec836b51a`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy#policy)

### Description

 This check identifies if an AWS IAM role policy grants the `iam:CreateLoginProfile` action with a `Resource` set to `"*"`, as shown below:

```
policy = jsonencode({
  Version = "2012-10-17"
  Statement = [
    {
      Action = [
        "iam:CreateLoginProfile",
      ]
      Effect   = "Allow"
      Resource = "*"
    },
  ]
})
```

Allowing this action enables a user or role to create login profiles (that is, set console passwords) for any IAM user account, potentially facilitating privilege escalation. If left unaddressed, attackers could exploit this permission to gain unauthorized console access and take full control of IAM users, posing a severe security risk to the environment.


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
          "iam:CreateLoginProfile",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}



```