---
title: "User with privilege escalation by actions 'ec2:RunInstances' and 'iam:PassRole'"
group_id: "Terraform / AWS"
meta:
  name: "aws/user_with_privilege_escalation_by_actions_iam_PassRole_and_ec2_RunInstances"
  id: "89561b03-cb35-44a9-a7e9-8356e71606f4"
  display_name: "User with privilege escalation by actions 'ec2:RunInstances' and 'iam:PassRole'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `89561b03-cb35-44a9-a7e9-8356e71606f4`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_user_policy#policy)

### Description

 Granting a user the `'ec2:RunInstances'` and `'iam:PassRole'` permissions with the resource set to `'*'` allows them to launch EC2 instances and attach any IAM role, potentially escalating their privileges beyond intended limits. 

For example, the following configuration is unsafe:

```
policy = jsonencode({
  Version = "2012-10-17"
  Statement = [
    {
      Action = [
        "iam:PassRole",
      ]
      Effect   = "Allow"
      Resource = "*"
    },
    {
      Action = [
        "ec2:RunInstances",
      ]
      Effect   = "Allow"
      Resource = "*"
    },
  ]
})
```

This vulnerability can enable attackers to assume highly privileged roles and gain full administrative access to AWS resources, leading to compromise of the entire cloud environment if left unaddressed. Access to these actions should be tightly scoped with least privilege and limited to essential roles.


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
          "ec2:RunInstances",
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
  policy_arn = aws_iam_policy.policy.arn
}


resource "aws_iam_policy" "policy" {
  name        = "test-policy"
  description = "A test policy"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "iam:PassRole",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

```