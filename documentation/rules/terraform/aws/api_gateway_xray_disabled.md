---
title: "API Gateway X-Ray disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/api_gateway_xray_disabled"
  id: "5813ef56-fa94-406a-b35d-977d4a56ff2b"
  display_name: "API Gateway X-Ray disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `5813ef56-fa94-406a-b35d-977d4a56ff2b`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage#xray_tracing_enabled)

### Description

 Enabling X-Ray tracing in AWS API Gateway stages provides detailed observability by capturing request traces, which are essential for monitoring, debugging, and identifying performance bottlenecks or errors in distributed applications. When the Terraform configuration for an API Gateway stage omits the attribute `xray_tracing_enabled`, or explicitly sets `xray_tracing_enabled = false`, as shown below, tracing is disabled:

```
resource "aws_api_gateway_stage" "example" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.test.id
  deployment_id = aws_api_gateway_deployment.test.id
  xray_tracing_enabled = false
}
```

Without X-Ray tracing, issues such as increased latency or failed requests may go undetected and unresolved, limiting visibility into the lifecycle of requests as they traverse backend integrations and microservices. Leaving tracing disabled increases operational risks and reduces the ability to promptly identify and remediate failures or security incidents, ultimately impacting the reliability and security of the API service.


## Compliant Code Examples
```terraform
resource "aws_api_gateway_stage" "negative1" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.test.id
  deployment_id = aws_api_gateway_deployment.test.id
  xray_tracing_enabled = true
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_api_gateway_stage" "positive1" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.test.id
  deployment_id = aws_api_gateway_deployment.test.id
  xray_tracing_enabled = false
}

resource "aws_api_gateway_stage" "positive2" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.test.id
  deployment_id = aws_api_gateway_deployment.test.id
}
```