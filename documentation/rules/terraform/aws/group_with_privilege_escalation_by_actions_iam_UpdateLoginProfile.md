---
title: "Group with privilege escalation by actions 'iam:UpdateLoginProfile'"
group_id: "Terraform / AWS"
meta:
  name: "aws/group_with_privilege_escalation_by_actions_iam_UpdateLoginProfile"
  id: "ad296c0d-8131-4d6b-b030-1b0e73a99ad3"
  display_name: "Group with privilege escalation by actions 'iam:UpdateLoginProfile'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `ad296c0d-8131-4d6b-b030-1b0e73a99ad3`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy#policy)

### Description

 Allowing an IAM group the `iam:UpdateLoginProfile` action on all resources (`"Resource": "*"`) is a significant privilege escalation risk. With this permission, any user in the group can reset or change the console password of any IAM user in the AWS account, effectively taking over their credentials. If left unaddressed, malicious or compromised users could gain access to higher privileges, potentially leading to unauthorized access, data exfiltration, or service disruption.


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
          "iam:UpdateLoginProfile",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


```