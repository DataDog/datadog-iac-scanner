---
title: "SNS topic is publicly accessible"
group_id: "Terraform / AWS"
meta:
  name: "aws/sns_topic_is_publicly_accessible"
  id: "b26d2b7e-60f6-413d-a3a1-a57db24aa2b3"
  display_name: "SNS topic is publicly accessible"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `b26d2b7e-60f6-413d-a3a1-a57db24aa2b3`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic)

### Description

This check verifies that Amazon SNS topic policies do not allow public access by having wildcard principals in their IAM policies. When an SNS topic policy includes a principal with wildcard (`*`) or allows anonymous access, it makes the topic publicly accessible to any AWS account, potentially exposing sensitive information or allowing unauthorized message publishing/consumption.

Secure configuration requires specifying explicit IAM principals rather than using wildcards. For example, instead of using `"AWS": "*"` which grants access to anyone, use a specific account ARN like `"AWS": "arn:aws:iam::account_number:root"` to limit access to authorized entities only. This prevents unauthorized access to your SNS topics and their messages.

## Compliant Code Examples
```terraform
resource "aws_sns_topic" "negative1" {
policy = <<EOF
{
"Version": "2012-10-17",
"Statement": [
{
"Action": "*",
"Principal": {
  "AWS": "arn:aws:iam::##account_number##:root"
},
"Effect": "Allow",
"Sid": ""
}
]
}
EOF
}


```
## Non-Compliant Code Examples
```terraform
resource "aws_sns_topic" "positive1" {
policy = <<EOF
{
"Version": "2012-10-17",
"Statement": [
{
"Action": "*",
"Principal": {
  "AWS": "*"
},
"Effect": "Allow",
"Sid": ""
}
]
}
EOF
}

```