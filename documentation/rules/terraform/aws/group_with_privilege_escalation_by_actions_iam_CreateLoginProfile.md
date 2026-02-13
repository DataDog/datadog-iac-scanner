---
title: "Group with privilege escalation by actions 'iam:CreateLoginProfile'"
group_id: "Terraform / AWS"
meta:
  name: "aws/group_with_privilege_escalation_by_actions_iam_CreateLoginProfile"
  id: "04c686f1-e0cd-4812-88e1-4e038410074c"
  display_name: "Group with privilege escalation by actions 'iam:CreateLoginProfile'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `04c686f1-e0cd-4812-88e1-4e038410074c`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy#policy)

### Description

 Granting a group the `iam:CreateLoginProfile` action with a `Resource` set to `"*"` in an IAM policy allows any user in that group to create or reset the console password for any IAM user in the account. This enables privilege escalation, as attackers or unauthorized users can create login profiles for privileged IAM users, effectively gaining their access. Leaving this misconfiguration unaddressed can lead to account compromise and full administrative access over AWS resources.


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
          "iam:CreateLoginProfile",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


```