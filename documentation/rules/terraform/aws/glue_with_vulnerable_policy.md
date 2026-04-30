---
title: "Glue with vulnerable policy"
group_id: "Terraform / AWS"
meta:
  name: "aws/glue_with_vulnerable_policy"
  id: "terraform-aws-glue-with-vulnerable-policy"
  display_name: "Glue with vulnerable policy"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `terraform-aws-glue-with-vulnerable-policy`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_resource_policy#policy)

### Description

Resource-based policies for AWS Glue should not use wildcard values (`"*"`) in the `principals` or `actions` attributes, as shown in the example below:

```
principals {
  identifiers = ["*"]
  type        = "AWS"
}
actions = ["glue:*"]
```

Allowing all actions and granting access to any principal exposes the Glue resources to unauthorized access or privilege escalation, significantly increasing the risk of data breaches or malicious modifications. Restricting both principals and allowed actions to the minimum necessary set reduces the attack surface and enforces least privilege.

## Compliant Code Examples
```terraform
data "aws_iam_policy_document" "glue-example-policy2" {
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

resource "aws_glue_resource_policy" "example2" {
  policy = data.aws_iam_policy_document.glue-example-policy2.json
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_glue_resource_policy" "multi_statement" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Safe",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": ["glue:GetTable"]
    },
    {
      "Sid": "Vulnerable",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["glue:*"]
    }
  ]
}
POLICY
}

```

```terraform
resource "aws_glue_resource_policy" "jsonencoded" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "JsonEncodedVulnerable"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["glue:*"]
      }
    ]
  })
}

```

```terraform
data "aws_iam_policy_document" "glue-example-policy" {
  statement {
    actions = [
      "glue:*",
    ]
    resources = ["arn:data.aws_partition.current.partition:glue:data.aws_region.current.name:data.aws_caller_identity.current.account_id:*"]
    principals {
      identifiers = ["*"]
      type        = "AWS"
    }
  }
}

resource "aws_glue_resource_policy" "example" {
  policy = data.aws_iam_policy_document.glue-example-policy.json
}

```