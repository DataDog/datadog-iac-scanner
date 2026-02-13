---
title: "IAM policy grants full permissions"
group_id: "Terraform / AWS"
meta:
  name: "aws/iam_policy_grants_full_permissions"
  id: "575a2155-6af1-4026-b1af-d5bc8fe2a904"
  display_name: "IAM policy grants full permissions"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `575a2155-6af1-4026-b1af-d5bc8fe2a904`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy)

### Description

 IAM policies that grant full administrative permissions (`*`) to all resources pose a significant security risk by violating the principle of least privilege. If these credentials are compromised, attackers gain unrestricted access to your AWS environment, potentially leading to data breaches, resource destruction, or cryptocurrency mining. Instead of using wildcard permissions, specify only the actions and resources necessary for the role or user, such as limiting to specific services and resources, as shown below:

Insecure example:
```json
"Action": ["*"],
"Effect": "Allow",
"Resource": "*"
```

Secure example:
```json
"Action": [
  "ec2:*",
  "s3:*",
  "lambda:*", 
  "cloudwatch:*"
],
"Effect": "Allow",
"Resource": "SomeResource"
```


## Compliant Code Examples
```terraform
resource "aws_iam_policy" "s3-permission" {
  name   = "s3-permission"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "*"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:iam::aws:policy/AdministratorAccess"
    }
  ]
}
EOF
}

```

```terraform
resource "aws_iam_policy" "s3-permission" {
  name   = "s3-permission"
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
      "Resource": "SomeResource"
    }
  ]
}
EOF
}

```

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

resource "aws_iam_user_policy" "negative3" {
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
      "Resource": "SomeResource"
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
resource "aws_iam_policy" "s3-permission" {
  name   = "s3-permission"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

```

```terraform
resource "aws_iam_user" "positive1" {
  name          = "${local.resource_prefix.value}-user"
  force_destroy = true

  tags = {
    Name        = "${local.resource_prefix.value}-user"
    Environment = local.resource_prefix.value
  }

}

resource "aws_iam_access_key" "positive2" {
  user = aws_iam_user.user.name
}

resource "aws_iam_user_policy" "positive3" {
  name = "excess_policy"
  user = aws_iam_user.user.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
      "*"
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