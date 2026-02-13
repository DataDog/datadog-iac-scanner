---
title: "Role with privilege escalation by actions 'iam:CreateAccessKey'"
group_id: "Terraform / AWS"
meta:
  name: "aws/role_with_privilege_escalation_by_actions_iam_CreateAccessKey"
  id: "5b4d4aee-ac94-4810-9611-833636e5916d"
  display_name: "Role with privilege escalation by actions 'iam:CreateAccessKey'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `5b4d4aee-ac94-4810-9611-833636e5916d`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy#policy)

### Description

 Allowing the `iam:CreateAccessKey` action on all resources (i.e., with `Resource = "*"`) in an IAM role policy is a privilege escalation risk. This configuration enables any principal with access to this role to create new access keys for any IAM user in the AWS account, potentially including users with higher privileges. Attackers or unauthorized users could abuse this permission to generate access keys for privileged users, thereby gaining elevated access to sensitive resources. Failing to restrict this action through more precise resource ARNs or additional conditions greatly increases the risk of account compromise and unauthorized activity. 

In Terraform, an insecure configuration example looks like the following:

```
resource "aws_iam_role_policy" "test_inline_policy" {
  ...
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "iam:CreateAccessKey",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}
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
          "iam:CreateAccessKey",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}


```