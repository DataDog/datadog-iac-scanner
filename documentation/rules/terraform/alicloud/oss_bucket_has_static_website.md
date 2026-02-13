---
title: "OSS bucket has static website"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/oss_bucket_has_static_website"
  id: "2b13c6ff-b87a-484d-86fd-21ef6e97d426"
  display_name: "OSS bucket has static website"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `2b13c6ff-b87a-484d-86fd-21ef6e97d426`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#website)

### Description

Checks whether any static websites are hosted on OSS buckets by detecting the `website` attribute in `alicloud_oss_bucket` resources. Buckets with the `website` attribute are flagged, as static website hosting may lead to unintended public exposure or accidental content hosting. The rule reports an `IncorrectValue` when `website` is present. Be aware of any website configurations in use.

## Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket-acl1" {
  bucket = "bucket-1-acl"
  acl    = "private"
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket-website1" {
  bucket = "bucket-1-website"

  website {
    index_document = "index.html"
    error_document = "error.html"
  }
}

```