---
title: "CloudWatch logs destination with vulnerable policy"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudwatch_logs_destination_with_vulnerable_policy"
  id: "db0ec4c4-852c-46a2-b4f3-7ec13cdb12a8"
  display_name: "CloudWatch logs destination with vulnerable policy"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Access Control"
---
## Metadata

**Id:** `db0ec4c4-852c-46a2-b4f3-7ec13cdb12a8`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_destination_policy#access_policy)

### Description

CloudWatch Logs destination policies should not use wildcards ('*') in the `principals` or `actions` fields, as this can inadvertently grant broad permissions. When wildcards are used, any AWS principal may gain permission to perform any logs-related actions, increasing the risk of unauthorized access or data exfiltration. Attackers or unintentional actors could potentially send or retrieve log data, modify log subscriptions, or disrupt monitoring workflows. Restricting both `principals` and `actions` to only necessary accounts and actions protects log data integrity and helps maintain the security of monitoring operations.

## Compliant Code Examples
```terraform
data "aws_iam_policy_document" "test_destination_policy2" {
  statement {
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        "123456789012",
      ]
    }

    actions = [
      "logs:PutSubscriptionFilter",
    ]

    resources = [
      aws_cloudwatch_log_destination.test_destination.arn,
    ]
  }
}

resource "aws_cloudwatch_log_destination_policy" "test_destination_policy2" {
  destination_name = aws_cloudwatch_log_destination.test_destination.name
  access_policy    = data.aws_iam_policy_document.test_destination_policy2.json
}

```
## Non-Compliant Code Examples
```terraform
data "aws_iam_policy_document" "test_destination_policy" {
  statement {
    effect = "Allow"

    principals {
      type = "AWS"

      identifiers = [
        data.aws_caller_identity.current.id,
      ]
    }

    actions = [
      "logs:*",
    ]

  }
}

resource "aws_cloudwatch_log_destination_policy" "test_destination_policy" {
  destination_name = aws_cloudwatch_log_destination.test_destination.name
  access_policy    = data.aws_iam_policy_document.test_destination_policy.json
}

```