---
title: "Group with privilege escalation by actions 'iam:AddUserToGroup'"
group_id: "Terraform / AWS"
meta:
  name: "aws/group_with_privilege_escalation_by_actions_iam_AddUserToGroup"
  id: "970ed7a2-0aca-4425-acf1-0453c9ecbca1"
  display_name: "Group with privilege escalation by actions 'iam:AddUserToGroup'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `970ed7a2-0aca-4425-acf1-0453c9ecbca1`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy#policy)

### Description

 Granting the `iam:AddUserToGroup` action with the `Resource` attribute set to `*` in an AWS IAM policy allows any user to add themselves or any other user to any IAM group within the AWS account. This wide permission can enable unauthorized privilege escalation, as users could gain access to groups with higher-level privileges, potentially bypassing intended access controls. If left unaddressed, attackers or compromised users may escalate their privileges and gain broader access to sensitive resources, severely impacting the security of the environment. To mitigate this risk, restrict the `Resource` field to specific group ARNs and ensure only trusted users have the ability to manage IAM group memberships.


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
          "iam:AddUserToGroup",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

```