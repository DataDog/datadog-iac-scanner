---
title: "REST API with vulnerable policy"
group_id: "Terraform / AWS"
meta:
  name: "aws/rest_api_with_vulnerable_policy"
  id: "b161c11b-a59b-4431-9a29-4e19f63e6b27"
  display_name: "REST API with vulnerable policy"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `b161c11b-a59b-4431-9a29-4e19f63e6b27`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_rest_api_policy#policy)

### Description

 This check ensures that REST API policies do not use wildcard values for the `Action` and `Principal` fields. Using a wildcard (`"*"`) in the `Principal` field allows any AWS user to invoke the API, and a wildcard in the `Action` field grants permissions for all possible API Gateway actions. This overly permissive configuration introduces a critical security vulnerability, as it permits unauthorized users to execute any API Gateway action, potentially leading to data exposure, unauthorized system manipulation, or service disruption. Restricting these fields to specific users and actions is necessary to enforce least privilege and mitigate the risk of API abuse or compromise.


## Compliant Code Examples
```terraform
resource "aws_api_gateway_rest_api" "test" {
  name = "example-rest-api"
}

resource "aws_api_gateway_rest_api_policy" "test" {
  rest_api_id = aws_api_gateway_rest_api.test.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::123456789012:user/test-user"
        ]
      },
      "Action": "execute-api:Invoke",
      "Resource": "aws_api_gateway_rest_api.test.execution_arn",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "123.123.123.123/32"
        }
      }
    }
  ]
}
EOF
}

```
## Non-Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-1"
}

resource "aws_api_gateway_rest_api" "api_gw" {
  name        = "api-gw-cache-encrypted"
  description = "API GW test"
}



resource "aws_api_gateway_rest_api_policy" "test" {
  rest_api_id = aws_api_gateway_rest_api.api_gw.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "execute-api:*",
      "Resource": "${aws_api_gateway_rest_api.api_gw.arn}"
    }
  ]
}
EOF
}


resource "aws_api_gateway_deployment" "api_gw_deploy" {
  depends_on  = [aws_api_gateway_integration.api_gw_int]
  rest_api_id = aws_api_gateway_rest_api.api_gw.id
  stage_name  = "dev"
}

resource "aws_api_gateway_resource" "api_gw_resource" {
  rest_api_id = aws_api_gateway_rest_api.api_gw.id
  parent_id   = aws_api_gateway_rest_api.api_gw.root_resource_id
  path_part   = "mytestresource"
}

resource "aws_api_gateway_method" "api_gw_method" {
  rest_api_id   = aws_api_gateway_rest_api.api_gw.id
  resource_id   = aws_api_gateway_resource.api_gw_resource.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "api_gw_int" {
  rest_api_id = aws_api_gateway_rest_api.api_gw.id
  resource_id = aws_api_gateway_resource.api_gw_resource.id
  http_method = aws_api_gateway_method.api_gw_method.http_method
  type        = "MOCK"

  request_templates = {
    "application/xml" = <<EOF
{
   "body" : $input.json('$')
}
EOF
  }
}

resource "aws_api_gateway_stage" "api_gw_stage" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.api_gw.id
  deployment_id = aws_api_gateway_deployment.api_gw_deploy.id
}

resource "aws_api_gateway_method_settings" "api_gw_method_sett" {
  rest_api_id = aws_api_gateway_rest_api.api_gw.id
  stage_name  = aws_api_gateway_stage.api_gw_stage.stage_name
  method_path = "${aws_api_gateway_resource.api_gw_resource.path_part}/${aws_api_gateway_method.api_gw_method.http_method}"

  settings {
    logging_level        = "OFF"
    caching_enabled      = true # This is required for cache encryption
    cache_data_encrypted = true # This is required for cache encryption
  }
}

```