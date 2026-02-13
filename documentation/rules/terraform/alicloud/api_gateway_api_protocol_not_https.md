---
title: "API gateway API protocol not HTTPS"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/api_gateway_api_protocol_not_https"
  id: "1bcdf9f0-b1aa-40a4-b8c6-cd7785836843"
  display_name: "API gateway API protocol not HTTPS"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `1bcdf9f0-b1aa-40a4-b8c6-cd7785836843`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/api_gateway_api#protocol)

### Description

API Gateway APIs must use `HTTPS`.
This rule flags `alicloud_api_gateway_api` resources where `request_config.protocol` is not set to `HTTPS`.
It supports both single and indexed forms of `request_config`, and reports the resource name and attribute location.

## Compliant Code Examples
```terraform
resource "alicloud_api_gateway_group" "apiGroup" {
  name        = "ApiGatewayGroup"
  description = "description of the api group"
}

resource "alicloud_api_gateway_api" "apiGatewayApi" {
  name        = alicloud_api_gateway_group.apiGroup.name
  group_id    = alicloud_api_gateway_group.apiGroup.id
  description = "your description"
  auth_type   = "APP"
  force_nonce_check = false

  request_config {
    protocol = "HTTPS"
    method   = "GET"
    path     = "/test/path1"
    mode     = "MAPPING"
  }

  service_type = "HTTP"

  http_service_config {
    address   = "https://apigateway-backend.alicloudapi.com:8080"
    method    = "GET"
    path      = "/web/cloudapi"
    timeout   = 12
    aone_name = "cloudapi-openapi"
  }

  request_parameters {
    name         = "aaa"
    type         = "STRING"
    required     = "OPTIONAL"
    in           = "QUERY"
    in_service   = "QUERY"
    name_service = "testparams"
  }

  stage_names = [
    "RELEASE",
    "TEST",
  ]
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_api_gateway_group" "apiGroup" {
  name        = "ApiGatewayGroup"
  description = "description of the api group"
}

resource "alicloud_api_gateway_api" "apiGatewayApi" {
  name        = alicloud_api_gateway_group.apiGroup.name
  group_id    = alicloud_api_gateway_group.apiGroup.id
  description = "your description"
  auth_type   = "APP"
  force_nonce_check = false

  request_config {
    protocol = "HTTP"
    method   = "GET"
    path     = "/test/path1"
    mode     = "MAPPING"
  }

  request_config {
    protocol = "HTTP"
    method   = "GET"
    path     = "/test/path2"
    mode     = "MAPPING"
  }

  service_type = "HTTP"

  http_service_config {
    address   = "http://apigateway-backend.alicloudapi.com:8080"
    method    = "GET"
    path      = "/web/cloudapi"
    timeout   = 12
    aone_name = "cloudapi-openapi"
  }

  request_parameters {
    name         = "aaa"
    type         = "STRING"
    required     = "OPTIONAL"
    in           = "QUERY"
    in_service   = "QUERY"
    name_service = "testparams"
  }

  stage_names = [
    "RELEASE",
    "TEST",
  ]
}

```

```terraform
resource "alicloud_api_gateway_group" "apiGroup" {
  name        = "ApiGatewayGroup"
  description = "description of the api group"
}

resource "alicloud_api_gateway_api" "apiGatewayApi" {
  name        = alicloud_api_gateway_group.apiGroup.name
  group_id    = alicloud_api_gateway_group.apiGroup.id
  description = "your description"
  auth_type   = "APP"
  force_nonce_check = false

  request_config {
    protocol = "HTTP"
    method   = "GET"
    path     = "/test/path1"
    mode     = "MAPPING"
  }

  service_type = "HTTP"

  http_service_config {
    address   = "http://apigateway-backend.alicloudapi.com:8080"
    method    = "GET"
    path      = "/web/cloudapi"
    timeout   = 12
    aone_name = "cloudapi-openapi"
  }

  request_parameters {
    name         = "aaa"
    type         = "STRING"
    required     = "OPTIONAL"
    in           = "QUERY"
    in_service   = "QUERY"
    name_service = "testparams"
  }

  stage_names = [
    "RELEASE",
    "TEST",
  ]
}

```