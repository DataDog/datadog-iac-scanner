---
title: "Athena workgroup not encrypted"
group_id: "Terraform / AWS"
meta:
  name: "aws/athena_workgroup_not_encrypted"
  id: "d364984a-a222-4b5f-a8b0-e23ab19ebff3"
  display_name: "Athena workgroup not encrypted"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `d364984a-a222-4b5f-a8b0-e23ab19ebff3`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup#encryption_configuration)

### Description

Amazon Athena workgroups must have encryption configured to protect sensitive query results stored in S3 buckets. Without encryption, query results containing sensitive data could be exposed to unauthorized users if the S3 bucket is compromised, potentially leading to data breaches and compliance violations. The encryption configuration should be included within the `result_configuration` block by specifying an `encryption_option` (such as `SSE_KMS`) and providing a KMS key ARN, as shown in the following example:

```terraform
resource "aws_athena_workgroup" "example" {
  configuration {
    result_configuration {
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.example.arn
      }
    }
  }
}
```

## Compliant Code Examples
```terraform
resource "aws_athena_workgroup" "example" {
  name = "example"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.example.bucket}/output/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.example.arn
      }
    }
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_athena_workgroup" "example" {
  name = "example"
}

resource "aws_athena_workgroup" "example_2" {
  name = "example"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
  }
}

resource "aws_athena_workgroup" "example_3" {
  name = "example"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
    }
  }
}

```