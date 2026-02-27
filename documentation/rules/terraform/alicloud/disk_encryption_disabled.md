---
title: "Disk encryption disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/disk_encryption_disabled"
  id: "39750e32-3fe9-453b-8c33-dd277acdb2cc"
  display_name: "Disk encryption disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `39750e32-3fe9-453b-8c33-dd277acdb2cc`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/disk#encrypted)

### Description

Alicloud disks (`alicloud_disk`) should have encryption enabled.

The rule flags resources where the `encrypted` attribute is explicitly set to `false` (issue type `IncorrectValue`) or where both the `encrypted` and `snapshot_id` attributes are missing (issue type `MissingAttribute`).

Remediation is to set `encrypted` to `true` (replacement) or add `encrypted = true` (addition).

## Compliant Code Examples
```terraform
resource "alicloud_disk" "disk_encryption3" {
  # cn-beijing
  availability_zone = "cn-beijing-b"
  name              = "New-disk"
  description       = "Hello ecs disk."
  category          = "cloud_efficiency"
  size              = "30"
  encrypted         = true
  kms_key_id        = "2a6767f0-a16c-4679-a60f-13bf*****"
  tags = {
    Name = "TerraformTest"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_disk" "disk_encryption2" {
  # cn-beijing
  availability_zone = "cn-beijing-b"
  name              = "New-disk"
  description       = "Hello ecs disk."
  category          = "cloud_efficiency"
  size              = "30"
  encrypted         = false
  kms_key_id        = "2a6767f0-a16c-4679-a60f-13bf*****"
  tags = {
    Name = "TerraformTest"
  }
}

```

```terraform
resource "alicloud_disk" "disk_encryption1" {
  # cn-beijing
  availability_zone = "cn-beijing-b"
  name              = "New-disk"
  description       = "Hello ecs disk."
  category          = "cloud_efficiency"
  size              = "30"
  tags = {
    Name = "TerraformTest"
  }
}


```