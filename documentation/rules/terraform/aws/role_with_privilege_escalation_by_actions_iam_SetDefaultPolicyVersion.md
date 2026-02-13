---
title: "Role with privilege escalation by actions 'iam:SetDefaultPolicyVersion'"
group_id: "Terraform / AWS"
meta:
  name: "aws/role_with_privilege_escalation_by_actions_iam_SetDefaultPolicyVersion"
  id: "118281d0-6471-422e-a7c5-051bc667926e"
  display_name: "Role with privilege escalation by actions 'iam:SetDefaultPolicyVersion'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `118281d0-6471-422e-a7c5-051bc667926e`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy#policy)

### Description

 Granting the `iam:SetDefaultPolicyVersion` action with a resource value of `"*"` allows a user or role to set any version of any IAM policy as the default, enabling potential privilege escalation. If an attacker can create or update a policy version containing more permissive permissions and set it as default, they can grant themselves or others broader access to AWS resources. This misconfiguration can lead to compromised account security and unauthorized actions if not properly restricted.


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
          "iam:SetDefaultPolicyVersion",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


```