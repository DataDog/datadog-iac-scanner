---
title: "CloudTrail logging disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudtrail_logging_disabled"
  id: "4bb76f17-3d63-4529-bdca-2b454529d774"
  display_name: "CloudTrail logging disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `4bb76f17-3d63-4529-bdca-2b454529d774`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#enable_logging)

### Description

This check ensures that logging is enabled for AWS CloudTrail by verifying that the `enable_logging` attribute is set to `true` in the resource configuration. Disabling logging (`enable_logging = false`) prevents the capture of API activity in your AWS account, which can hinder threat detection, audit investigations, and incident response efforts. For security and compliance, CloudTrail logging should always be enabled, as shown below:

```
resource "aws_cloudtrail" "example" {
  name           = "example"
  s3_bucket_name = "bucketlog"
  enable_logging = true
}
```

## Compliant Code Examples
```terraform
resource "aws_cloudtrail" "negative1" {
  name                          = "negative_1"
  s3_bucket_name                = "bucketlog"
  enable_logging                = true
}

resource "aws_cloudtrail" "negative2" {
  name                          = "negative_2"
  s3_bucket_name                = "bucketlog"
}
```
## Non-Compliant Code Examples
```terraform
#this is a problematic code where the query should report a result(s)
resource "aws_cloudtrail" "positive1" {
  name                          = "positive"
  s3_bucket_name                = "bucketlog"
  enable_logging                = false
}
```