---
title: "OSS bucket public access enabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/oss_bucket_public_access_enabled"
  id: "62232513-b16f-4010-83d7-51d0e1d45426"
  display_name: "OSS bucket public access enabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `62232513-b16f-4010-83d7-51d0e1d45426`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#acl)

### Description

OSS buckets should have public access disabled. This rule flags `alicloud_oss_bucket` resources where `acl` is set to `public-read` or `public-read-write`. To restrict access, set `acl = "private"` or remove the `acl` attribute.

## Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket_public_access_enabled4" {
  bucket = "bucket-170309-acl"
}

```

```terraform
resource "alicloud_oss_bucket" "bucket_public_access_enabled1" {
  bucket = "bucket-170309-acl"
  acl    = "private"
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket_public_access_enabled3" {
  bucket = "bucket-170309-acl"
  acl    = "public-read-write"
}

resource "alicloud_oss_bucket" "bucket-logging" {
  bucket = "bucket-170309-logging"

  logging {
    target_bucket = alicloud_oss_bucket.bucket-target.id
    target_prefix = "log/"
  }
}

```

```terraform
resource "alicloud_oss_bucket" "bucket_public_access_enabled2" {
  bucket = "bucket-170309-acl"
  acl    = "public-read"
}

```