---
title: "CMK is unusable"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/cmk_is_unusable"
  id: "ed6e3ba0-278f-47b6-a1f5-173576b40b7e"
  display_name: "CMK is unusable"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Availability"
---
## Metadata

**Id:** `ed6e3ba0-278f-47b6-a1f5-173576b40b7e`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Availability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/kms_key#is_enabled)

### Description

 Alicloud KMS must only include enabled Customer Master Keys (CMKs). This rule flags `alicloud_kms_key` resources when:

- `is_enabled` is explicitly set to false (`IncorrectValue`), or
- `is_enabled` is missing (`MissingAttribute`)

To remediate, set or update `is_enabled = true`.


## Compliant Code Examples
```terraform
resource "alicloud_kms_key" "key" {
  description             = "Hello KMS"
  pending_window_in_days  = "7"
  status                  = "Enabled"
  is_enabled              = true
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_kms_key" "key" {
  description             = "Hello KMS"
  pending_window_in_days  = "7"
  status                  = "Enabled"
  is_enabled              = false
}

```

```terraform
resource "alicloud_kms_key" "key" {
  description             = "Hello KMS"
  pending_window_in_days  = "7"
  status                  = "Enabled"
}

```