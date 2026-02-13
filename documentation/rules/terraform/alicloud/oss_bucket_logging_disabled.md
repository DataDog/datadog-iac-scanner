---
title: "OSS bucket logging disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/oss_bucket_logging_disabled"
  id: "05db341e-de7d-4972-a106-3e2bd5ee53e1"
  display_name: "OSS bucket logging disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `05db341e-de7d-4972-a106-3e2bd5ee53e1`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#logging)

### Description

 OSS buckets should have logging enabled to improve visibility into resource and object access.  The `alicloud_oss_bucket` resource must include a `logging` block with `logging_isenable` set to `true`. If the `logging` block is missing or `logging_isenable` is `false`, access logging is not enabled. To remediate, add the block or update `logging_isenable` from `false` to `true`.


## Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket_logging1" {
  bucket = "bucket-170309-logging"

  logging {
    target_bucket = alicloud_oss_bucket.bucket-target.id
    target_prefix = "log/"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket_logging1" {
  bucket = "bucket-170309-logging"
  logging_isenable = false

  logging {
    target_bucket = alicloud_oss_bucket.bucket-target.id
    target_prefix = "log/"
  }
}

```

```terraform
resource "alicloud_oss_bucket" "bucket_logging2" {
  bucket = "bucket-170309-acl"
  acl    = "public-read"
}

```