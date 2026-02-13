---
title: "Public Lambda via API Gateway"
group_id: "Terraform / AWS"
meta:
  name: "aws/public_lambda_via_api_gateway"
  id: "3ef8696c-e4ae-4872-92c7-520bb44dfe77"
  display_name: "Public Lambda via API Gateway"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `3ef8696c-e4ae-4872-92c7-520bb44dfe77`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission)

### Description

 Allowing a Lambda function to be invoked through a public API Gateway endpoint can introduce security vulnerabilities by exposing the function to the internet. This configuration grants invocation permissions on the Lambda function from any HTTP method and any resource within the associated API Gateway, as illustrated by the use of the wildcard `"/*/*"` in the ARN. If left unaddressed, attackers could exploit the public endpoint to trigger the Lambda function, potentially resulting in unauthorized data access, denial-of-service attacks, or increased costs due to unwanted invocations. To mitigate this risk, permissions should be restricted to only necessary resources and specific methods, thereby limiting the surface area exposed to the public.


## Compliant Code Examples
```terraform
resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.example.function_name
  principal     = "apigateway.amazonaws.com"

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
  source_arn = "${aws_api_gateway_rest_api.example.execution_arn}/test/test"
}

resource "aws_lambda_function" "example" {
  function_name = "ServerlessPerson"

  handler = "MyHandler::handleRequest"
  runtime = "java11"

  role = aws_iam_role.lambda_exec.arn
}


```
## Non-Compliant Code Examples
```terraform
resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.example.function_name
  principal     = "apigateway.amazonaws.com"

  # The "/*/*" portion grants access from any method on any resource
  # within the API Gateway REST API.
  source_arn = "${aws_api_gateway_rest_api.example.execution_arn}/*/*"
}

resource "aws_lambda_function" "example" {
  function_name = "ServerlessPerson"

  handler = "MyHandler::handleRequest"
  runtime = "java11"

  role = aws_iam_role.lambda_exec.arn
}


```