---
title: "API Gateway stage without API Gateway usage plan associated"
group_id: "Terraform / AWS"
meta:
  name: "aws/api_gateway_stage_without_api_gateway_usage_plan_associated"
  id: "c999cf62-0920-40f8-8dda-0caccd66ed7e"
  display_name: "API Gateway stage without API Gateway usage plan associated"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Resource Management"
---
## Metadata

**Id:** `c999cf62-0920-40f8-8dda-0caccd66ed7e`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage)

### Description

API Gateway stages should always be associated with an API Gateway UsagePlan, which enforces throttling and quota limits for clients accessing your APIs. Without a defined `aws_api_gateway_usage_plan` resource and its association via the `api_stages` block, as shown below, the API stage can be accessed without usage restrictions, leading to potential misuse, abuse, or denial of service due to unlimited traffic.

```
resource "aws_api_gateway_stage" "example" {
  deployment_id = "some deployment id"
  rest_api_id   = "some rest api id"
  stage_name    = "development"
}
```

Configuring a UsagePlan, such as the one in the example below, helps mitigate these risks by controlling consumption through quotas and throttling, protecting backend resources and maintaining predictable API performance.

```
resource "aws_api_gateway_usage_plan" "example" {
  name        = "my-usage-plan"
  description = "usage plan description"
  api_stages {
    api_id = "some rest api id"
    stage  = "development"
  }
}
```

## Compliant Code Examples
```terraform
resource "aws_api_gateway_stage" "negative1" {
  deployment_id = "some deployment id"
  rest_api_id   = "rest_api_1"
  stage_name    = "development"
}

resource "aws_api_gateway_usage_plan" "negative2" {
  name         = "my-usage-plan"
  description  = "my description"
  product_code = "MYCODE"

  api_stages {
    api_id = "rest_api_1"
    stage  = "development"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_api_gateway_stage" "positive1" {
  rest_api_id   = "some deployment id"
  deployment_id = "some rest api id"
  stage_name = "some name"
  tags {
    project = "ProjectName"
  }
}

resource "aws_api_gateway_stage" "positive2" {
  deployment_id = "some deployment id"
  rest_api_id   = "some rest api id"
  stage_name    = "development"
}

resource "aws_api_gateway_usage_plan" "positive3" {
  name         = "my-usage-plan"
  description  = "my description"
  product_code = "MYCODE"

  api_stages {
    api_id = "another id"
    stage  = "development"
  }
}

```