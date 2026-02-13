---
title: "Log retention is not greater than 90 days"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/log_retention_is_not_greater_than_90_days"
  id: "ed6cf6ff-9a1f-491c-9f88-e03c0807f390"
  display_name: "Log retention is not greater than 90 days"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `ed6cf6ff-9a1f-491c-9f88-e03c0807f390`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/log_store#retention_period)

### Description

 The OSS Log Store must have `retention_period` set to at least 90 days to ensure sufficient visibility into resource and object activity.  
If `retention_period` is undefined, the default is 30 days, which is insufficient.  
Resources of type `alicloud_log_store` should explicitly set `retention_period` to 90 or more days (for example, `100`).  
This rule flags `alicloud_log_store` resources that either omit `retention_period` or set it to less than 90 days.


## Compliant Code Examples
```terraform
resource "alicloud_log_project" "example1" {
  name        = "tf-log"
  description = "created by terraform"
}

resource "alicloud_log_store" "example1" {
  project               = alicloud_log_project.example.name
  name                  = "tf-log-store"
  retention_period      = 91
  shard_count           = 3
  auto_split            = true
  max_split_shard_count = 60
  append_meta           = true
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_log_project" "example4" {
  name        = "tf-log"
  description = "created by terraform"
}

resource "alicloud_log_store" "example4" {
  project               = alicloud_log_project.example.name
  name                  = "tf-log-store"
  retention_period      = 60
  shard_count           = 3
  auto_split            = true
  max_split_shard_count = 60
  append_meta           = true
}

```

```terraform
resource "alicloud_log_project" "example2" {
  name        = "tf-log"
  description = "created by terraform"
}

resource "alicloud_log_store" "example2" {
  project               = alicloud_log_project.example.name
  name                  = "tf-log-store"
  shard_count           = 3
  auto_split            = true
  max_split_shard_count = 60
  append_meta           = true
}

```