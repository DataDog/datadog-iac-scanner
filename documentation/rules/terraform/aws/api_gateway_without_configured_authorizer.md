---
title: "API Gateway without configured authorizer"
group_id: "Terraform / AWS"
meta:
  name: "aws/api_gateway_without_configured_authorizer"
  id: "0a96ce49-4163-4ee6-8169-eb3b0797d694"
  display_name: "API Gateway without configured authorizer"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `0a96ce49-4163-4ee6-8169-eb3b0797d694`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_authorizer)

### Description

This check ensures that all AWS API Gateway REST APIs have an associated API Gateway authorizer, which is responsible for validating incoming requests before granting access to backend resources. Without specifying an authorizer using the `aws_api_gateway_authorizer` resource and linking it to the `rest_api_id` attribute in your Terraform configuration, APIs may be left unprotected, allowing unauthenticated and potentially malicious users to access sensitive endpoints. Failure to enforce proper authorization can result in unauthorized access, data exposure, or abuse of backend services.

## Compliant Code Examples
```terraform
resource "aws_api_gateway_authorizer" "demo" {
  name                   = "demo"
  rest_api_id            = aws_api_gateway_rest_api.demo.id
  authorizer_uri         = aws_lambda_function.authorizer.invoke_arn
  authorizer_credentials = aws_iam_role.invocation_role.arn
}

resource "aws_api_gateway_rest_api" "demo" {
  name = "auth-demo"
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_api_gateway_authorizer" "demo" {
  name                   = "demo"
  rest_api_id            = aws_api_gateway_rest_api.demo.id
  authorizer_uri         = aws_lambda_function.authorizer.invoke_arn
  authorizer_credentials = aws_iam_role.invocation_role.arn
}

resource "aws_api_gateway_rest_api" "demo2" {
  name = "auth-demo"
}

```