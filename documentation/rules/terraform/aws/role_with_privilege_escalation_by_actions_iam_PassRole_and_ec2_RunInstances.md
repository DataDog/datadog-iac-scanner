---
title: "Role with privilege escalation by actions 'ec2:RunInstances' and 'iam:PassRole'"
group_id: "Terraform / AWS"
meta:
  name: "aws/role_with_privilege_escalation_by_actions_iam_PassRole_and_ec2_RunInstances"
  id: "30b88745-eebe-4ecb-a3a9-5cf886e96204"
  display_name: "Role with privilege escalation by actions 'ec2:RunInstances' and 'iam:PassRole'"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `30b88745-eebe-4ecb-a3a9-5cf886e96204`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy#policy)

### Description

 Granting an IAM role permissions for both `ec2:RunInstances` and `iam:PassRole` with their `Resource` attribute set to `"*"` enables a privilege escalation pathway in AWS. This configuration allows any user or entity assuming the role to launch new EC2 instances and assign any IAM role in the account to those instances, including roles with more expansive permissions. As a result, attackers can potentially gain administrative access by launching an instance with a privileged role, bypassing the originally intended limitations. If left unaddressed, this misconfiguration can result in full compromise of the AWS account’s resources, leading to data loss, service disruption, or unauthorized access to sensitive workloads.


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
  roles      = [aws_iam_role.cosmic.name]
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