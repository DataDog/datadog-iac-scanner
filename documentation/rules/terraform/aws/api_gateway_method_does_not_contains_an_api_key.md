---
title: "API Gateway method does not contains an API key"
group_id: "Terraform / AWS"
meta:
  name: "aws/api_gateway_method_does_not_contains_an_api_key"
  id: "671211c5-5d2a-4e97-8867-30fc28b02216"
  display_name: "API Gateway method does not contains an API key"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `671211c5-5d2a-4e97-8867-30fc28b02216`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method)

### Description

When defining an `aws_api_gateway_method` resource in Terraform, it is critical to require an API key on method requests by setting the attribute `api_key_required = true`. If this option is set to `false` or omitted (as shown below), unauthorized clients can invoke the API method without providing an API key, exposing the endpoint to potential abuse and unauthorized access.

```
resource "aws_api_gateway_method" "insecure_example" {
  rest_api_id      = aws_api_gateway_rest_api.MyDemoAPI.id
  resource_id      = aws_api_gateway_resource.MyDemoResource.id
  http_method      = "GET"
  authorization    = "NONE"
  api_key_required = false
}
```

Failing to enforce API key requirements can lead to security risks such as credential-less access to sensitive endpoints, excessive traffic, and increased risk of denial-of-service attacks.

## Compliant Code Examples
```terraform
resource "aws_api_gateway_method" "negative1" {
  rest_api_id       = aws_api_gateway_rest_api.MyDemoAPI.id
  resource_id       = aws_api_gateway_resource.MyDemoResource.id
  http_method       = "GET"
  authorization     = "NONE"
  api_key_required  = true
}


```
## Non-Compliant Code Examples
```terraform
resource "aws_api_gateway_method" "positive1" {
  rest_api_id       = aws_api_gateway_rest_api.MyDemoAPI.id
  resource_id       = aws_api_gateway_resource.MyDemoResource.id
  http_method       = "GET"
  authorization     = "NONE"
}

resource "aws_api_gateway_method" "positive2" {
  rest_api_id       = aws_api_gateway_rest_api.MyDemoAPI.id
  resource_id       = aws_api_gateway_resource.MyDemoResource.id
  http_method       = "GET"
  authorization     = "NONE"
  api_key_required  = false
}


```