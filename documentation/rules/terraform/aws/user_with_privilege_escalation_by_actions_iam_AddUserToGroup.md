---
title: "User with privilege escalation by actions 'iam:AddUserToGroup'"
group_id: "Terraform / AWS"
meta:
  name: "aws/user_with_privilege_escalation_by_actions_iam_AddUserToGroup"
  id: "bf9d42c7-c2f9-4dfe-942c-c8cc8249a081"
  display_name: "User with privilege escalation by actions 'iam:AddUserToGroup'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `bf9d42c7-c2f9-4dfe-942c-c8cc8249a081`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_user_policy#policy)

### Description

Granting the `iam:AddUserToGroup` permission with a resource scope of `"*"` allows the associated IAM user to add themselves or any other user to any group in the AWS account, regardless of the group's assigned permissions. This effectively enables privilege escalation, as the user could insert themselves into groups with administrative or other high-privilege roles, circumventing intended policy boundaries. If left unaddressed, this misconfiguration undermines the principle of least privilege and opens the door to unauthorized access, potentially leading to full compromise of the AWS environment. It is important to restrict such permissions to only trusted users and limit the resources they can affect to mitigate this risk.

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
          "iam:AddUserToGroup",
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