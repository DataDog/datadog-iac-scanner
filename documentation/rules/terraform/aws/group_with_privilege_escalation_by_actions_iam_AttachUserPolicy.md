---
title: "Group with privilege escalation by actions 'iam:AttachUserPolicy'"
group_id: "Terraform / AWS"
meta:
  name: "aws/group_with_privilege_escalation_by_actions_iam_AttachUserPolicy"
  id: "db78d14b-10e5-4e6e-84b1-dace6327b1ec"
  display_name: "Group with privilege escalation by actions 'iam:AttachUserPolicy'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `db78d14b-10e5-4e6e-84b1-dace6327b1ec`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy#policy)

### Description

Granting a group the `iam:AttachUserPolicy` action with `"Resource": "*"` in Terraform, as shown by the attribute and policy below, allows any group member to attach arbitrary IAM policies to any user in the AWS account. This creates a serious privilege escalation vulnerability, as users with this permission can grant themselves or others higher privileges, including administrative access, bypassing intended security controls. If left unaddressed, attackers could exploit this misconfiguration to gain unrestricted access or take over AWS resources.

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
          "iam:AttachUserPolicy",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

```