---
title: "User with privilege escalation by actions 'iam:PutUserPolicy'"
group_id: "Terraform / AWS"
meta:
  name: "aws/user_with_privilege_escalation_by_actions_iam_PutUserPolicy"
  id: "0c10d7da-85c4-4d62-b2a8-d6c104f1bd77"
  display_name: "User with privilege escalation by actions 'iam:PutUserPolicy'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `0c10d7da-85c4-4d62-b2a8-d6c104f1bd77`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_user_policy#policy)

### Description

 Granting a user the `iam:PutUserPolicy` action with a resource value of `"*"` allows that user to attach any policy to any IAM user, including themselves. This creates a privilege escalation vulnerability, as the user could grant themselves administrative permissions or access otherwise restricted resources. To mitigate this risk, permission sets should be strictly defined and limited; for example, only allowing non-privileged actions such as in the following example:

```
policy = jsonencode({
  Version = "2012-10-17"
  Statement = [
    {
      Action = [
        "ec2:Describe*"
      ]
      Effect   = "Allow"
      Resource = "*"
    }
  ]
})
```
Limiting permissions in this way reduces the risk of unauthorized privilege escalation.


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
          "iam:PutUserPolicy",
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