---
title: "Kinesis SSE not configured"
group_id: "Terraform / AWS"
meta:
  name: "aws/kinesis_sse_not_configured"
  id: "5c6dd5e7-1fe0-4cae-8f81-4c122717cef3"
  display_name: "Kinesis SSE not configured"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `5c6dd5e7-1fe0-4cae-8f81-4c122717cef3`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kinesis_firehose_delivery_stream#server_side_encryption)

### Description

 AWS Kinesis Firehose delivery streams should have Server-Side Encryption (SSE) properly configured to protect sensitive data at rest. Without encryption, data stored in Kinesis streams can be exposed to unauthorized access, potentially leading to data breaches and compliance violations. To secure Kinesis streams, the `server_side_encryption` block must be included with `enabled` set to `true` and a valid `key_type` specified (either `AWS_OWNED_CMK` or `CUSTOMER_MANAGED_CMK` with corresponding `key_arn`).
```
resource "aws_kinesis_firehose_delivery_stream" "example" {
  // ... other configuration ...
  
  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = "arn:aws:kms:region:account-id:key/key-id"
  }
}
```


## Compliant Code Examples
```terraform

resource "aws_kinesis_firehose_delivery_stream" "negative1" {
  name        = "${aws_s3_bucket.logs.bucket}-firehose"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = "qwewewre"
  }
}




resource "aws_kinesis_firehose_delivery_stream" "negative2" {
  name        = "${aws_s3_bucket.logs.bucket}-firehose"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "AWS_OWNED_CMK"
  }
}


```
## Non-Compliant Code Examples
```terraform
resource "aws_kinesis_firehose_delivery_stream" "positive1" {
  name        = "${aws_s3_bucket.logs.bucket}-firehose"
  destination = "extended_s3"

  kinesis_source_configuration {
    kinesis_stream_arn = aws_kinesis_stream.cloudwatch-logs.arn
    role_arn           = aws_iam_role.firehose_role.arn
  }
}


resource "aws_kinesis_firehose_delivery_stream" "positive2" {
  name        = "${aws_s3_bucket.logs.bucket}-firehose"
  destination = "extended_s3"
}


resource "aws_kinesis_firehose_delivery_stream" "positive3" {
  name        = "${aws_s3_bucket.logs.bucket}-firehose"
  destination = "extended_s3"

  server_side_encryption {
    enabled = false
  }
}


resource "aws_kinesis_firehose_delivery_stream" "positive4" {
  name        = "${aws_s3_bucket.logs.bucket}-firehose"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "AWS_OWN"
  }
}

resource "aws_kinesis_firehose_delivery_stream" "positive5" {
  name        = "${aws_s3_bucket.logs.bucket}-firehose"
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
  }
}

```