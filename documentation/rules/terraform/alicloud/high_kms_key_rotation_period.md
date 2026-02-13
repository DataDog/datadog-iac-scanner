---
title: "High KMS key rotation period"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/high_kms_key_rotation_period"
  id: "cb319d87-b90f-485e-a7e7-f2408380f309"
  display_name: "High KMS key rotation period"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `cb319d87-b90f-485e-a7e7-f2408380f309`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/kms_key)

### Description

KMS keys should have automatic rotation enabled, and the rotation period must not exceed one year. This rule converts the resource's `rotation_interval` (supports suffixes `s`, `m`, `h`, `d`) to seconds and flags values greater than `31536000`. It also requires `automatic_rotation` to be set to `Enabled`; missing or `Disabled` values are reported. To remediate, set `rotation_interval = "365d"` and `automatic_rotation = "Enabled"`.

## Compliant Code Examples
```terraform
resource "alicloud_kms_key" "key" {
  description             = "Hello KMS"
  pending_window_in_days  = "7"
  status                  = "Enabled"
  automatic_rotation      = "Enabled"
  rotation_interval      = "7d"
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_kms_key" "keypos1" {
  description             = "Hello KMS"
  pending_window_in_days  = "7"
  status                  = "Enabled"
  automatic_rotation      = "Enabled"
  rotation_interval      = "366d"
}

```

```terraform
resource "alicloud_kms_key" "keypos1" {
  description             = "Hello KMS"
  pending_window_in_days  = "7"
  status                  = "Enabled"
  automatic_rotation      = "Enabled"
  rotation_interval      = "31536010s"
}

```

```terraform
resource "alicloud_kms_key" "keypos1" {
  description             = "Hello KMS"
  pending_window_in_days  = "7"
  status                  = "Enabled"
  automatic_rotation      = "Disabled"
}

```