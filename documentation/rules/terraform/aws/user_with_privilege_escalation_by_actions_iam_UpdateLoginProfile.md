---
title: "User with privilege escalation by actions 'iam:UpdateLoginProfile'"
group_id: "Terraform / AWS"
meta:
  name: "aws/user_with_privilege_escalation_by_actions_iam_UpdateLoginProfile"
  id: "6deb34e2-5d9c-499a-801b-ea6d9eda894f"
  display_name: "User with privilege escalation by actions 'iam:UpdateLoginProfile'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `6deb34e2-5d9c-499a-801b-ea6d9eda894f`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_user_policy#policy)

### Description

 Allowing a user the `iam:UpdateLoginProfile` permission with the `Resource` set to `"*"` in Terraform, as in the following example, enables that user to change the passwords of any IAM user in the AWS account:

```
Action = [
  "iam:UpdateLoginProfile",
]
Resource = "*"
```

This creates a privilege escalation risk, as the user could assign themselves or others passwords to high-privilege accounts, resulting in unauthorized access or control over critical resources. If left unaddressed, this misconfiguration can lead to account compromise and the potential for significant security incidents.


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
          "iam:UpdateLoginProfile",
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