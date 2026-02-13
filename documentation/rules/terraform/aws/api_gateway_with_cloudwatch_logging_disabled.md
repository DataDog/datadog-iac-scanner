---
title: "API Gateway with CloudWatch logging disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/api_gateway_with_cloudwatch_logging_disabled"
  id: "982aa526-6970-4c59-8b9b-2ce7e019fe36"
  display_name: "API Gateway with CloudWatch logging disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `982aa526-6970-4c59-8b9b-2ce7e019fe36`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage#managing-the-api-logging-cloudwatch-log-group)

### Description

 Enabling AWS CloudWatch Logs for API Gateway stages is critical for capturing execution logs and monitoring API access and activity. If the log group name is misconfigured and does not follow the required naming convention, such as using an incorrect variable (`${var.stage_names}` instead of `${var.stage_name}`), logs may not be associated correctly with their respective API Gateway stages, resulting in reduced visibility and hampering incident response efforts. The `aws_cloudwatch_log_group` resource should have its `name` attribute follow the pattern `"API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.example.id}/${var.stage_name}"` to ensure proper alignment with AWS best practices and support effective auditing and troubleshooting.


## Compliant Code Examples
```terraform
module "env" {
  source = "./env"
}

resource "aws_api_gateway_rest_api" "example" {
  # ... other configuration ...
}

resource "aws_api_gateway_stage" "example" {
  depends_on = [aws_cloudwatch_log_group.example]

  stage_name = module.env.vars.stage_name
  # ... other configuration ...
}

resource "aws_cloudwatch_log_group" "example" {
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.example.id}/${module.env.vars.stage_name}"
  retention_in_days = 7
  # ... potentially other configuration ...
}

```

```terraform
variable "stage_name" {
  default = "example"
  type    = string
}

resource "aws_api_gateway_rest_api" "example" {
  # ... other configuration ...
}

resource "aws_api_gateway_stage" "example" {
  depends_on = [aws_cloudwatch_log_group.example]

  stage_name = var.stage_name
  # ... other configuration ...
}

resource "aws_cloudwatch_log_group" "example" {
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.example.id}/${var.stage_name}"
  retention_in_days = 7
  # ... potentially other configuration ...
}

```
## Non-Compliant Code Examples
```terraform
variable "stage_name" {
  default = "example"
  type    = string
}
variable "stage_names" {
  default = "examples"
  type    = string
}

resource "aws_api_gateway_rest_api" "example" {
  # ... other configuration ...
}

resource "aws_api_gateway_stage" "example" {
  depends_on = [aws_cloudwatch_log_group.example]

  stage_name = var.stage_name
  # ... other configuration ...
}

resource "aws_cloudwatch_log_group" "example" {
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.example.id}/${var.stage_names}"
  retention_in_days = 7
  # ... potentially other configuration ...
}

```