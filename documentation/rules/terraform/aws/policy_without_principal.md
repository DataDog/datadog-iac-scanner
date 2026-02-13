---
title: "Policy without principal"
group_id: "Terraform / AWS"
meta:
  name: "aws/policy_without_principal"
  id: "bbe3dd3d-fea9-4b68-a785-cfabe2bbbc54"
  display_name: "Policy without principal"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `bbe3dd3d-fea9-4b68-a785-cfabe2bbbc54`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html)

### Description

 When defining resource-based policies in AWS using Terraform, the `Principal` element must be explicitly set to specify which users, roles, or accounts are permitted to access the resource. If the `Principal` element is omitted in policies other than IAM identity-based policies, the permissions may unintentionally allow access to any AWS user, potentially enabling unauthorized or malicious actions on the resource. For example, a secure policy includes the `"Principal"` attribute, restricting permissions to specific users:

```
"Principal": {
  "AWS": [
    "arn:aws:iam::AWS-account-ID:user/user-name-1",
    "arn:aws:iam::AWS-account-ID:user/UserName2"
  ]
}
```
Neglecting to define the `Principal` in resource-based policies significantly increases the risk of unauthorized access or privilege escalation.


## Compliant Code Examples
```terraform
data "aws_iam_policy_document" "glue-example-policyX" {
  statement {
    actions = [
      "glue:CreateTable",
    ]
    resources = ["arn:data.aws_partition.current.partition:glue:data.aws_region.current.name:data.aws_caller_identity.current.account_id:*"]
    principals {
      identifiers = ["arn:aws:iam::var.account_id:saml-provider/var.provider_name"]
      type        = "AWS"
    }
  }
}

resource "aws_glue_resource_policy" "exampleX" {
  policy = data.aws_iam_policy_document.glue-example-policyX.json
}

```

```terraform
resource "aws_iam_user" "user" {
  name = "test-user"
}

resource "aws_iam_role" "role" {
  name = "test-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_group" "group" {
  name = "test-group"
}

resource "aws_iam_policy" "policy" {
  name        = "test-policy"
  description = "A test policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:Describe*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_policy_attachment" "test-attach" {
  name       = "test-attachment"
  users      = [aws_iam_user.user.name]
  roles      = [aws_iam_role.role.name]
  groups     = [aws_iam_group.group.name]
  policy_arn = aws_iam_policy.policy.arn
}

```

```terraform
provider "aws" {
  region = "us-east-1"
}

resource "aws_kms_key" "secure_policy" {
  description             = "KMS key + secure_policy"
  deletion_window_in_days = 7

  policy = <<EOF
{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "Secure Policy",
            "Effect": "Allow",
            "Resource": "*",
            "Action": [
            "kms:Create*",
            "kms:Describe*",
            "kms:Enable*",
            "kms:List*",
            "kms:Put*",
            "kms:Update*",
            "kms:Revoke*",
            "kms:Disable*",
            "kms:Get*",
            "kms:Delete*",
            "kms:TagResource",
            "kms:UntagResource",
            "kms:ScheduleKeyDeletion",
            "kms:CancelKeyDeletion"
            ],
            "Principal": "AWS": [
              "arn:aws:iam::AWS-account-ID:user/user-name-1",
              "arn:aws:iam::AWS-account-ID:user/UserName2"
            ]
        }
    ]
}
EOF
}

```
## Non-Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-1"
}

resource "aws_kms_key" "secure_policy" {
  description             = "KMS key + secure_policy"
  deletion_window_in_days = 7

  policy = <<EOF
{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "Secure Policy",
            "Effect": "Allow",
            "Resource": "*",
            "Action": [
            "kms:Create*",
            "kms:Describe*",
            "kms:Enable*",
            "kms:List*",
            "kms:Put*",
            "kms:Update*",
            "kms:Revoke*",
            "kms:Disable*",
            "kms:Get*",
            "kms:Delete*",
            "kms:TagResource",
            "kms:UntagResource",
            "kms:ScheduleKeyDeletion",
            "kms:CancelKeyDeletion"
            ]
        }
    ]
}
EOF
}

```