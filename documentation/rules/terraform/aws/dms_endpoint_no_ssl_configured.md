---
title: "DMS endpoints without SSL"
group_id: "Terraform / AWS"
meta:
  name: "aws/dms_endpoint_no_ssl_configured"
  id: "e6f7g8h9-i0j1-4klm-56no-7890pqrstu12"
  display_name: "DMS endpoints without SSL"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `e6f7g8h9-i0j1-4klm-56no-7890pqrstu12`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dms_endpoint#ssl_mode)

### Description

AWS Database Migration Service (DMS) endpoints without SSL encryption leave sensitive data exposed during transmission between source and target databases. When SSL mode is set to `none`, database credentials and data are transmitted in plaintext, potentially allowing attackers to intercept and capture confidential information. To secure your endpoints, ensure the `ssl_mode` parameter is set to `require` rather than `none`, as shown below:

```
resource "aws_dms_endpoint" "example" {
  endpoint_id   = "example-endpoint"
  endpoint_type = "source"
  engine_name   = "mysql"
  ssl_mode      = "require"  // Secure configuration
}
```

## Compliant Code Examples
```terraform
resource "aws_dms_endpoint" "good_example_exempt_source" {
  endpoint_id   = "example-source-s3"
  endpoint_type = "source"
  engine_name   = "s3"
  ssl_mode      = "none" # ✅ S3 source is exempt
}

resource "aws_dms_endpoint" "good_example_exempt_target" {
  endpoint_id   = "example-target-kinesis"
  endpoint_type = "target"
  engine_name   = "kinesis"
  ssl_mode      = "none" # ✅ Kinesis target is exempt
}

```

```terraform
resource "aws_dms_endpoint" "good_example_source" {
  endpoint_id   = "example-source"
  endpoint_type = "source"
  engine_name   = "mysql"
  ssl_mode      = "require" # ✅ SSL is enabled
}

resource "aws_dms_endpoint" "good_example_target" {
  endpoint_id   = "example-target"
  endpoint_type = "target"
  engine_name   = "postgres"
  ssl_mode      = "require" # ✅ SSL is enabled
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_dms_endpoint" "bad_example_source" {
  endpoint_id   = "example-source"
  endpoint_type = "source"
  engine_name   = "mysql"
  ssl_mode      = "none" # ❌ SSL is disabled for a non-exempt source endpoint
}

resource "aws_dms_endpoint" "bad_example_target" {
  endpoint_id   = "example-target"
  endpoint_type = "target"
  engine_name   = "postgres"
  ssl_mode      = "none" # ❌ SSL is disabled for a non-exempt target endpoint
}

```