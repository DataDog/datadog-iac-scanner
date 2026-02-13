---
title: "CloudWatch metrics disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudwatch_metrics_disabled"
  id: "081069cb-588b-4ce1-884c-2a1ce3029fe5"
  display_name: "CloudWatch metrics disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `081069cb-588b-4ce1-884c-2a1ce3029fe5`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings#metrics_enabled)

### Description

This check determines whether Amazon API Gateway stages are properly configured to enable CloudWatch metrics by verifying that the `metrics_enabled` attribute is set to `true` within the `settings` block. If `metrics_enabled` is set to `false` or omitted, CloudWatch metrics will not capture API Gateway performance data, such as error rates, latency, or request counts. This lack of monitoring inhibits an organization's ability to detect misuse, troubleshoot issues, or respond to anomalous behaviors in their API environments. Without timely visibility into API activity, misconfigurations or security incidents may go unnoticed, increasing operational and security risks.

## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
resource "aws_api_gateway_method_settings" "negative1" {
  rest_api_id = aws_api_gateway_rest_api.test.id
  stage_name  = aws_api_gateway_stage.test.stage_name
  method_path = "${aws_api_gateway_resource.test.path_part}/${aws_api_gateway_method.test.http_method}"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
  }
}
```
## Non-Compliant Code Examples
```terraform
#this is a problematic code where the query should report a result(s)
resource "aws_api_gateway_method_settings" "positive1" {
  rest_api_id = aws_api_gateway_rest_api.test.id
  stage_name  = aws_api_gateway_stage.test.stage_name
  method_path = "${aws_api_gateway_resource.test.path_part}/${aws_api_gateway_method.test.http_method}"

  settings {
    metrics_enabled = false
    logging_level   = "INFO"
  }
}

resource "aws_api_gateway_method_settings" "positive2" {
  rest_api_id = aws_api_gateway_rest_api.test.id
  stage_name  = aws_api_gateway_stage.test.stage_name
  method_path = "${aws_api_gateway_resource.test.path_part}/${aws_api_gateway_method.test.http_method}"

  settings {
    logging_level   = "INFO"
  }
}
```