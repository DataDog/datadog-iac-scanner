---
title: "ActionTrail trail OSS bucket is publicly accessible"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/actiontrail_trail_oss_bucket_is_publicly_accessible"
  id: "69b5d7da-a5db-4db9-a42e-90b65d0efb0b"
  display_name: "ActionTrail trail OSS bucket is publicly accessible"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Observability"
---
## Metadata

**Id:** `69b5d7da-a5db-4db9-a42e-90b65d0efb0b`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** High

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/actiontrail_trail)

### Description

 The OSS bucket used by `alicloud_actiontrail_trail` must not be publicly accessible. This rule flags `alicloud_oss_bucket` resources with `acl` set to `public-read` or `public-read-write`, as these settings expose sensitive log data. The `acl` should be set to private to restrict access.


## Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket_actiontrail2" {
  bucket = "bucket_actiontrail_2"
}

resource "alicloud_actiontrail_trail" "actiontrail2" {
  trail_name         = "action-trail"
  oss_write_role_arn = "acs:ram::1182725xxxxxxxxxxx"
  oss_bucket_name    = "bucket_actiontrail_2"
  event_rw           = "All"
  trail_region       = "All"
}

```

```terraform
resource "alicloud_oss_bucket" "bucket_actiontrail1" {
  bucket = "bucket_actiontrail_1"
  acl    = "private"
}

resource "alicloud_actiontrail_trail" "actiontrail1" {
  trail_name         = "action-trail"
  oss_write_role_arn = "acs:ram::1182725xxxxxxxxxxx"
  oss_bucket_name    = "bucket_actiontrail_1"
  event_rw           = "All"
  trail_region       = "All"
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket_actiontrail4" {
  bucket = "bucket_actiontrail_4"
  acl    = "public-read-write"
}

resource "alicloud_actiontrail_trail" "actiontrail4" {
  trail_name         = "action-trail"
  oss_write_role_arn = "acs:ram::1182725xxxxxxxxxxx"
  oss_bucket_name    = "bucket_actiontrail_4"
  event_rw           = "All"
  trail_region       = "All"
}

```

```terraform
resource "alicloud_oss_bucket" "bucket_actiontrail3" {
  bucket = "bucket_actiontrail_3"
  acl    = "public-read"
}

resource "alicloud_actiontrail_trail" "actiontrail3" {
  trail_name         = "action-trail"
  oss_write_role_arn = "acs:ram::1182725xxxxxxxxxxx"
  oss_bucket_name    = "bucket_actiontrail_3"
  event_rw           = "All"
  trail_region       = "All"
}


```