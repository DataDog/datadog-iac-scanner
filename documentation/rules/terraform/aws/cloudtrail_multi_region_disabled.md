---
title: "CloudTrail multi region disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudtrail_multi_region_disabled"
  id: "8173d5eb-96b5-4aa6-a71b-ecfa153c123d"
  display_name: "CloudTrail multi region disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `8173d5eb-96b5-4aa6-a71b-ecfa153c123d`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#is_multi_region_trail)

### Description

Enabling multi-region trails in AWS CloudTrail ensures that all activity across all regions in an account is logged and monitored. Without setting the `is_multi_region_trail` and `include_global_service_events` attributes to `true`, activity in regions outside of the primary region or global service events may go unlogged, creating blind spots for potential unauthorized actions. To address this, the secure Terraform configuration should include `is_multi_region_trail = true` and `include_global_service_events = true`, as shown below:

```
resource "aws_cloudtrail" "secure_example" {
  name                          = "secure_trail"
  s3_bucket_name                = "secure_bucketlog"
  is_multi_region_trail         = true
  include_global_service_events = true
}
```

## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
resource "aws_cloudtrail" "negative1" {
  name                          = "negative"
  s3_bucket_name                = "bucketlog"
  is_multi_region_trail         = true
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_cloudtrail" "positive2" {
  name                          = "npositive_2"
  s3_bucket_name                = "bucketlog_2"
  is_multi_region_trail         = false
}

```

```terraform
resource "aws_cloudtrail" "positive3" {
  name                          = "npositive_3"
  s3_bucket_name                = "bucketlog_3"
  is_multi_region_trail         = true
  include_global_service_events = false
}

```

```terraform
#this is a problematic code where the query should report a result(s)
resource "aws_cloudtrail" "positive1" {
  name                          = "npositive_1"
  s3_bucket_name                = "bucketlog_1"
}

```