---
title: "API Gateway with invalid compression"
group_id: "Terraform / AWS"
meta:
  name: "aws/api_gateway_with_invalid_compression"
  id: "ed35928e-195c-4405-a252-98ccb664ab7b"
  display_name: "API Gateway with invalid compression"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Encryption"
---
## Metadata

**Id:** `ed35928e-195c-4405-a252-98ccb664ab7b`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_rest_api)

### Description

This check ensures that the `minimum_compression_size` attribute is set to a value greater than -1 and less than 10485760 for the `aws_api_gateway_rest_api` resource, enabling proper payload compression. Without valid configuration, API data transfer can be inefficient, leading to increased bandwidth costs and a slower experience for API consumers. Setting a secure configuration, such as shown below, ensures that response payloads are compressed appropriately, improving performance and security by preventing the misuse or neglect of compression settings.

```
resource "aws_api_gateway_rest_api" "example" {
  name = "regional-example"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  minimum_compression_size = 0
}
```

## Compliant Code Examples
```terraform
resource "aws_api_gateway_rest_api" "negative1" {
  name = "regional-example"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  minimum_compression_size = 0
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_api_gateway_rest_api" "positive1" {
  name = "regional-example"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}


resource "aws_api_gateway_rest_api" "positive2" {
  name = "regional-example"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  minimum_compression_size = -1
}


resource "aws_api_gateway_rest_api" "positive3" {
  name = "regional-example"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  minimum_compression_size = 10485760
}
```