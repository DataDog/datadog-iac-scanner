---
title: "User with privilege escalation by actions 'iam:CreateLoginProfile'"
group_id: "Terraform / AWS"
meta:
  name: "aws/user_with_privilege_escalation_by_actions_iam_CreateLoginProfile"
  id: "0fd7d920-4711-46bd-aff2-d307d82cd8b7"
  display_name: "User with privilege escalation by actions 'iam:CreateLoginProfile'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `0fd7d920-4711-46bd-aff2-d307d82cd8b7`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_user_policy#policy)

### Description

 Allowing users the `iam:CreateLoginProfile` action with the `Resource` set to `"*"` in AWS IAM policies permits them to set a password for any IAM user, thereby enabling direct console access. This creates a privilege escalation vulnerability, as the user can potentially assign login profiles to high-privilege accounts, leading to unauthorized access and control over critical AWS resources. To mitigate this risk, restrict the `Resource` to specific user ARNs and avoid assigning broad permissions, as shown in the following secure Terraform configuration:

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
          "iam:CreateLoginProfile",
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