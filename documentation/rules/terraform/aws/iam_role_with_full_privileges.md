---
title: "IAM role with full privileges"
group_id: "Terraform / AWS"
meta:
  name: "aws/iam_role_with_full_privileges"
  id: "b1ffa705-19a3-4b73-b9d0-0c97d0663842"
  display_name: "IAM role with full privileges"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `b1ffa705-19a3-4b73-b9d0-0c97d0663842`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role)

### Description

 IAM roles with full administrative privileges (using wildcard actions like `*`) grant unrestricted access to AWS resources, creating a significant security risk. If compromised, these roles could be exploited to access sensitive data, modify infrastructure, or launch attacks across your entire AWS environment. Instead of using wildcard permissions in the `Action` field, specify only the required permissions, as shown in the secure example:

```
"Action": ["some:action"]
```

Avoid insecure patterns such as the following:

```
"Action": ["*"] or "Action": "*"
```


## Compliant Code Examples
```terraform
resource "aws_iam_role" "negative1" {
  name = "test_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": ["some:action"],
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Resource": "*",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    tag-key = "tag-value"
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_iam_role" "positive1" {
  name = "test_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": ["*"],
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Resource": "*",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    tag-key = "tag-value"
  }
}

resource "aws_iam_role" "positive2" {
  name = "test_role2"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "*",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Resource": "*",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    tag-key = "tag-value"
  }
}
```