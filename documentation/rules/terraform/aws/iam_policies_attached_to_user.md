---
title: "IAM policies attached to user"
group_id: "Terraform / AWS"
meta:
  name: "aws/iam_policies_attached_to_user"
  id: "b4378389-a9aa-44ee-91e7-ef183f11079e"
  display_name: "IAM policies attached to user"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `b4378389-a9aa-44ee-91e7-ef183f11079e`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy_attachment)

### Description

IAM policies should be attached only to groups or roles to promote centralized permission management and reduce the risk of granting excessive privileges to individual users. Assigning an IAM policy directly to a user, as shown below with the `users` attribute, can increase the risk of credentials compromise or accidental permission escalation:

```
resource "aws_iam_policy_attachment" "positive1_3" {
  name = "excess_policy"
  users = [aws_iam_user.user.name]
  policy = <<EOF
  ...
EOF
}
```

If left unaddressed, this practice can lead to difficulties in auditing permissions and increases the attack surface, as any compromise of a single user account could grant broad and unrestricted access to resources.

## Compliant Code Examples
```terraform
resource "aws_iam_user" "negative1" {
  name          = "${local.resource_prefix.value}-user"
  force_destroy = true

  tags = {
    Name        = "${local.resource_prefix.value}-user"
    Environment = local.resource_prefix.value
  }

}

resource "aws_iam_access_key" "negative2" {
  user = aws_iam_user.user.name
}

resource "aws_iam_policy_attachment" "negative3" {
  name = "excess_policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:*",
        "s3:*",
        "lambda:*",
        "cloudwatch:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

output "username" {
  value = aws_iam_user.user.name
}

output "secret" {
  value = aws_iam_access_key.user.encrypted_secret
}


```
## Non-Compliant Code Examples
```terraform
resource "aws_iam_user" "positive2_1" {
  name          = "${local.resource_prefix.value}-user"
  force_destroy = true

  tags = {
    Name        = "${local.resource_prefix.value}-user"
    Environment = local.resource_prefix.value
  }

}

resource "aws_iam_access_key" "positive2_2" {
  user = aws_iam_user.user.name
}

resource "aws_iam_user_policy" "positive2_3" {
  name = "excess_policy"
  user = aws_iam_user.user.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:*",
        "s3:*",
        "lambda:*",
        "cloudwatch:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

output "username" {
  value = aws_iam_user.user.name
}

output "secret" {
  value = aws_iam_access_key.user.encrypted_secret
}


```

```terraform
resource "aws_iam_user" "user" {
  name = "test-user"
}

resource "aws_iam_policy" "policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
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

resource "aws_iam_user_policy_attachment" "test-attach" {
  user       = aws_iam_user.user.name
  policy_arn = aws_iam_policy.policy.arn
}

```

```terraform
resource "aws_iam_user" "positive1_1" {
  name          = "${local.resource_prefix.value}-user"
  force_destroy = true

  tags = {
    Name        = "${local.resource_prefix.value}-user"
    Environment = local.resource_prefix.value
  }

}

resource "aws_iam_access_key" "positive1_2" {
  user = aws_iam_user.user.name
}

resource "aws_iam_policy_attachment" "positive1_3" {
  name = "excess_policy"
  users = [aws_iam_user.user.name]

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:*",
        "s3:*",
        "lambda:*",
        "cloudwatch:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

output "username" {
  value = aws_iam_user.user.name
}

output "secret" {
  value = aws_iam_access_key.user.encrypted_secret
}


```