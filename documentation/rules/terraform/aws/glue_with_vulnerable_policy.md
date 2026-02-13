---
title: "Glue with vulnerable policy"
group_id: "Terraform / AWS"
meta:
  name: "aws/glue_with_vulnerable_policy"
  id: "d25edb51-07fb-4a73-97d4-41cecdc53a22"
  display_name: "Glue with vulnerable policy"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `d25edb51-07fb-4a73-97d4-41cecdc53a22`

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