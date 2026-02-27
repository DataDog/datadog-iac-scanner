---
title: "CloudWatch without retention period specified"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudwatch_without_retention_period_specified"
  id: "ef0b316a-211e-42f1-888e-64efe172b755"
  display_name: "CloudWatch without retention period specified"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `ef0b316a-211e-42f1-888e-64efe172b755`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group)

### Description

CloudWatch log groups in AWS should explicitly specify the `retention_in_days` attribute to control how long log data is stored. If this attribute is omitted or set to `0`, as shown below, logs are retained indefinitely, increasing storage costs and the risk of sensitive data exposure over time:

```
resource "aws_cloudwatch_log_group" "example" {
  name = "application-logs"
  retention_in_days = 0
}
```

A secure configuration, specifying `retention_in_days`, ensures log data is automatically deleted after the defined period, reducing unnecessary data retention and helping meet compliance requirements:

```
resource "aws_cloudwatch_log_group" "example" {
  name = "application-logs"
  retention_in_days = 7
}
```

## Compliant Code Examples
```terraform
resource "aws_cloudwatch_log_group" "negative1" {
  name = "Yada"

  tags = {
    Environment = "production"
    Application = "serviceA"
  }

  retention_in_days = 1
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_cloudwatch_log_group" "positive1" {
  name = "Yada"

  tags = {
    Environment = "production"
    Application = "serviceA"
  }
}

resource "aws_cloudwatch_log_group" "positive2" {
  name = "Yada"

  tags = {
    Environment = "production"
    Application = "serviceA"
  }

  retention_in_days = 0
}

```