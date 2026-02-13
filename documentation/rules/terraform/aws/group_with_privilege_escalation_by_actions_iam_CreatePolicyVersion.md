---
title: "Group with privilege escalation by actions 'iam:CreatePolicyVersion'"
group_id: "Terraform / AWS"
meta:
  name: "aws/group_with_privilege_escalation_by_actions_iam_CreatePolicyVersion"
  id: "ec49cbfd-fae4-45f3-81b1-860526d66e3f"
  display_name: "Group with privilege escalation by actions 'iam:CreatePolicyVersion'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `ec49cbfd-fae4-45f3-81b1-860526d66e3f`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy#policy)

### Description

 This check examines IAM group policies in Terraform configurations for the presence of overly permissive privileges, specifically the use of the `iam:CreatePolicyVersion` action with `Resource` set to `"*"`. Granting this permission allows group members to create new versions of any IAM managed policy, including those they do not own, enabling potential privilege escalation. An attacker with these rights could alter existing policies to grant themselves or others elevated permissions, thereby gaining unauthorized access to sensitive AWS resources. If left unaddressed, this misconfiguration poses a significant risk to the security and integrity of your AWS environment, as it breaks the principle of least privilege and could lead to full account compromise.


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
          "iam:CreatePolicyVersion",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


```