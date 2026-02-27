---
title: "EFS with vulnerable policy"
group_id: "Terraform / AWS"
meta:
  name: "aws/efs_with_vulnerable_policy"
  id: "fae52418-bb8b-4ac2-b287-0b9082d6a3fd"
  display_name: "EFS with vulnerable policy"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `fae52418-bb8b-4ac2-b287-0b9082d6a3fd`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/efs_file_system_policy#policy)

### Description

AWS EFS file system policies should avoid the use of wildcards (`*`) in the `Action` and `Principal` fields, as shown below, because this grants broad permissions to all users and all actions:

```
"Principal": { "AWS": "*" },
"Action": ["elasticfilesystem:*"]
```

Such overly permissive policies can allow any AWS account to perform any action on the EFS resource, leading to potential unauthorized data access, deletion, or modification. To mitigate this risk, restrict the `Principal` to specific IAM identities and limit `Action` to only what is necessary. For example:

```
"Principal": { "AWS": "arn:aws:iam::111122223333:user/Carlos" },
"Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"]
```

## Compliant Code Examples
```terraform
resource "aws_efs_file_system" "fs" {
  creation_token = "my-product"
}

resource "aws_efs_file_system_policy" "policy" {
  file_system_id = aws_efs_file_system.fs.id

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "ExamplePolicy01",
    "Statement": [
        {
            "Sid": "ExampleStatement01",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::111122223333:user/Carlos"
            }
            "Resource": "aws_efs_file_system.test.arn",
            "Action": [
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "true"
                }
            }
        }
    ]
}
POLICY
}

```
## Non-Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-1"
}

resource "aws_efs_file_system" "not_secure" {
  creation_token = "efs-not-secure"

  tags = {
    Name = "NotSecure"
  }
}

resource "aws_efs_file_system_policy" "not_secure_policy" {
  file_system_id = aws_efs_file_system.not_secure.id

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "ExamplePolicy01",
    "Statement": [
        {
            "Sid": "ExampleStatement01",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": [
                "elasticfilesystem:*"
            ]
        }
    ]
}
POLICY
}

```