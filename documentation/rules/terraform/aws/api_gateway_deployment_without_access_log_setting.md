---
title: "API Gateway deployment without access log setting"
group_id: "Terraform / AWS"
meta:
  name: "aws/api_gateway_deployment_without_access_log_setting"
  id: "625abc0e-f980-4ac9-a775-f7519ee34296"
  display_name: "API Gateway deployment without access log setting"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `625abc0e-f980-4ac9-a775-f7519ee34296`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_deployment)

### Description

 API Gateway deployments should have `access_log_settings` defined for each connected API Gateway Stage to ensure proper logging of API requests and responses. Without these settings, as shown below, critical API activity may go unlogged, making it difficult to track access patterns, detect malicious requests, or troubleshoot operational issues:

```
resource "aws_api_gateway_stage" "example" {
  ...
  access_log_settings {
    destination_arn = "arn:aws:logs:region:account-id:log-group:log-group-name"
    format          = "format"
  }
}
```

Leaving this misconfiguration unaddressed can hinder security monitoring and auditing, potentially exposing the environment to undetected abuse or data exfiltration.


## Compliant Code Examples
```terraform
resource "aws_api_gateway_deployment" "example5" {
  rest_api_id   = "some rest api id"
  stage_name = "some name"
  stage_description = "some description"

  tags {
    project = "ProjectName"
  }
}

resource "aws_api_gateway_stage" "example0" {
  deployment_id = aws_api_gateway_deployment.example5.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"

  access_log_settings {
    destination_arn = "dest"
    format = "format"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_api_gateway_deployment" "example3" {
  rest_api_id   = "some rest api id"
  stage_name = "some name"
  tags {
    project = "ProjectName"
  }
}

resource "aws_api_gateway_stage" "example000" {
  deployment_id = aws_api_gateway_deployment.example3.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"
}

```

```terraform
resource "aws_api_gateway_deployment" "example4" {
  rest_api_id   = "some rest api id"
  stage_name = "some name"
  tags {
    project = "ProjectName"
  }
}

resource "aws_api_gateway_stage" "example0000" {
  deployment_id = aws_api_gateway_deployment.example4.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"

  access_log_settings {
    destination_arn = "dest"
    format = "format"
  }
}

```

```terraform
resource "aws_api_gateway_deployment" "examplee" {
  rest_api_id   = "some rest api id"
  stage_name = "some name"
  tags {
    project = "ProjectName"
  }
}

resource "aws_api_gateway_stage" "example00" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"
}

```