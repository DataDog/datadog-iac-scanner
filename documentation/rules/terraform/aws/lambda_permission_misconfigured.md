---
title: "Lambda permission misconfigured"
group_id: "Terraform / AWS"
meta:
  name: "aws/lambda_permission_misconfigured"
  id: "75ec6890-83af-4bf1-9f16-e83726df0bd0"
  display_name: "Lambda permission misconfigured"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `75ec6890-83af-4bf1-9f16-e83726df0bd0`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission)

### Description

 This check verifies whether the `action` field in the `aws_lambda_permission` resource is set to `"lambda:InvokeFunction"`. When the field is misconfigured to allow actions beyond what is necessary, such as "lambda:DeleteFunction", it grants overly permissive access to the Lambda function. This can enable third-party AWS services or principals to perform destructive or unintended operations on the function, increasing the risk of unauthorized deletion, modification, or misuse. If left unaddressed, this misconfiguration could result in loss of critical business logic, disruption of service, or escalation of privileges within your cloud environment.


## Compliant Code Examples
```terraform
resource "aws_lambda_permission" "negative1" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.logging.function_name
  principal     = "logs.eu-west-1.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.default.arn}:*"
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_lambda_permission" "positive1" {
  action        = "lambda:DeleteFunction"
  function_name = aws_lambda_function.logging.function_name
  principal     = "logs.eu-west-1.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.default.arn}:*"
}

```