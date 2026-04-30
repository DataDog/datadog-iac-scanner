---
title: "Action trail logging for all regions disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/action_trail_logging_all_regions_disabled"
  id: "terraform-alicloud-action-trail-logging-for-all-regions-disabled"
  display_name: "Action trail logging for all regions disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `terraform-alicloud-action-trail-logging-for-all-regions-disabled`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/actiontrail_trail#trail_region)

### Description

ActionTrail logging must be enabled for all regions.
This rule checks that each `alicloud_actiontrail_trail` resource:

- Includes the `oss_bucket_name` attribute
- Sets both `event_rw` and `trail_region` attributes to `All`

Missing attributes trigger a `MissingAttribute` issue. Incorrect values trigger an `IncorrectValue` issue, with suggested remediation to add or correct the attribute.

## Compliant Code Examples
```terraform
resource "alicloud_actiontrail_trail" "actiontrail1" {
  trail_name         = "action-trail"
  oss_write_role_arn = "acs:ram::1182725xxxxxxxxxxx"
  oss_bucket_name    = "bucket_name"
  event_rw           = "All"
  trail_region       = "All"
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_actiontrail_trail" "actiontrail7" {
  trail_name         = "action-trail"
  oss_write_role_arn = "acs:ram::1182725xxxxxxxxxxx"
  oss_bucket_name    = "bucket_name"
  event_rw           = "Write"
  trail_region       = "cn-beijing"
}

```

```terraform
resource "alicloud_actiontrail_trail" "actiontrail3" {
  trail_name         = "action-trail"
  oss_write_role_arn = "acs:ram::1182725xxxxxxxxxxx"
  oss_bucket_name    = "bucket_name"
  event_rw           = "Read"
  trail_region       = "cn-hangzhou"
}

```

```terraform
resource "alicloud_actiontrail_trail" "actiontrail4" {
  trail_name         = "action-trail"
  oss_write_role_arn = "acs:ram::1182725xxxxxxxxxxx"
  oss_bucket_name    = "bucket_name"
  event_rw           = "Write"
  trail_region       = "cn-hangzhou"
}

```