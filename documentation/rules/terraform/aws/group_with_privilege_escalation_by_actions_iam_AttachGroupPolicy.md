---
title: "Group with privilege escalation by actions 'iam:AttachGroupPolicy'"
group_id: "Terraform / AWS"
meta:
  name: "aws/group_with_privilege_escalation_by_actions_iam_AttachGroupPolicy"
  id: "70b42736-efee-4bce-80d5-50358ed94990"
  display_name: "Group with privilege escalation by actions 'iam:AttachGroupPolicy'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `70b42736-efee-4bce-80d5-50358ed94990`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy#policy)

### Description

Allowing an IAM group the `iam:AttachGroupPolicy` action with a `Resource` set to `"*"` enables any user in that group to attach any policy, including those with administrator privileges, to any group. This creates a significant privilege escalation risk, where users can grant themselves or others far greater permissions than originally intended by attaching powerful policies. If left unaddressed, this can lead to full account compromise, unauthorized access, and loss of control over all AWS resources.

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
          "iam:AttachGroupPolicy",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}



```