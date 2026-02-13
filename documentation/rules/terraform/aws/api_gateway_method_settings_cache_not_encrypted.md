---
title: "API Gateway method settings cache not encrypted"
group_id: "Terraform / AWS"
meta:
  name: "aws/api_gateway_method_settings_cache_not_encrypted"
  id: "b7c9a40c-23e4-4a2d-8d39-a3352f10f288"
  display_name: "API Gateway method settings cache not encrypted"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `b7c9a40c-23e4-4a2d-8d39-a3352f10f288`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings#cache_data_encrypted)

### Description

When caching is enabled for API Gateway methods, sensitive data may be stored in the cache. If cache encryption is not enabled, this data remains vulnerable to unauthorized access, potentially exposing sensitive information. The `cache_data_encrypted` attribute should be explicitly set to `true` in the settings block of API Gateway method settings whenever caching is enabled.

Secure example:
```terraform
settings {
  metrics_enabled = true
  logging_level = "INFO"
  caching_enabled = true
  cache_data_encrypted = true
}
```

Insecure example:
```terraform
settings {
  metrics_enabled = true
  logging_level = "INFO"
  caching_enabled = true
  cache_data_encrypted = false  // or omitting this field
}
```

## Compliant Code Examples
```terraform
resource "aws_api_gateway_rest_api" "example" {
  body = jsonencode({
    openapi = "3.0.1"
    info = {
      title   = "example"
      version = "1.0"
    }
    paths = {
      "/path1" = {
        get = {
          x-amazon-apigateway-integration = {
            httpMethod           = "GET"
            payloadFormatVersion = "1.0"
            type                 = "HTTP_PROXY"
            uri                  = "https://ip-ranges.amazonaws.com/ip-ranges.json"
          }
        }
      }
    }
  })

  name = "example"
}

resource "aws_api_gateway_stage" "example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"
}

resource "aws_api_gateway_method_settings" "path_specific" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "path1/GET"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
    caching_enabled = true
    cache_data_encrypted = true
  }
}

resource "aws_api_gateway_method_settings" "path_specific_2" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "path1/GET"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
  }
}

resource "aws_api_gateway_method_settings" "path_specific_3" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "path1/GET"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
    caching_enabled = false
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_api_gateway_rest_api" "example" {
  body = jsonencode({
    openapi = "3.0.1"
    info = {
      title   = "example"
      version = "1.0"
    }
    paths = {
      "/path1" = {
        get = {
          x-amazon-apigateway-integration = {
            httpMethod           = "GET"
            payloadFormatVersion = "1.0"
            type                 = "HTTP_PROXY"
            uri                  = "https://ip-ranges.amazonaws.com/ip-ranges.json"
          }
        }
      }
    }
  })

  name = "example"
}

resource "aws_api_gateway_stage" "example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"
}

resource "aws_api_gateway_method_settings" "path_specific" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "path1/GET"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
    caching_enabled = true
    cache_data_encrypted = false
  }
}
resource "aws_api_gateway_method_settings" "path_specific_2" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "path1/GET"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
    caching_enabled = true
  }
}

```