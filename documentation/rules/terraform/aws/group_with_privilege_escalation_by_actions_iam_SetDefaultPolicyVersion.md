---
title: "Group with privilege escalation by actions 'iam:SetDefaultPolicyVersion'"
group_id: "Terraform / AWS"
meta:
  name: "aws/group_with_privilege_escalation_by_actions_iam_SetDefaultPolicyVersion"
  id: "7782d4b3-e23e-432b-9742-d9528432e771"
  display_name: "Group with privilege escalation by actions 'iam:SetDefaultPolicyVersion'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `7782d4b3-e23e-432b-9742-d9528432e771`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_group_policy#policy)

### Description

The configuration permits the `iam:SetDefaultPolicyVersion` action with a resource value of `"*"`, meaning members of the `aws_iam_group.cosmic` group are allowed to set any version of any IAM policy as the default. This is a dangerous privilege escalation vector, as it could allow attackers to promote a malicious or overly permissive policy version, potentially granting themselves or others administrative access across AWS resources. If left unaddressed, this vulnerability could be exploited to bypass least privilege principles, resulting in unauthorized access or control over critical AWS infrastructure. To mitigate this risk, restrict the allowable actions and resources in IAM policies and avoid assigning wildcard `"*"` resource permissions to sensitive actions such as `iam:SetDefaultPolicyVersion`.

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
          "iam:SetDefaultPolicyVersion",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


```