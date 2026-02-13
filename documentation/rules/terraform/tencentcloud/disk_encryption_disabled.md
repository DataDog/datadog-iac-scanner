---
title: "Beta - disk encryption disabled"
group_id: "Terraform / TencentCloud"
meta:
  name: "tencentcloud/disk_encryption_disabled"
  id: "1ee0f202-31da-49ba-bbce-04a989912e4b"
  display_name: "Beta - disk encryption disabled"
  cloud_provider: "TencentCloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `1ee0f202-31da-49ba-bbce-04a989912e4b`

**Cloud Provider:** TencentCloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/tencentcloudstack/tencentcloud/latest/docs/resources/cbs_storage#encrypt)

### Description

 Disks should have encryption enabled.
This rule checks `tencentcloud_cbs_storage` resources and flags when the `encrypt` attribute is missing or set to `false`.
The `encrypt` attribute must be set to `true` to ensure block storage volumes are encrypted.


## Compliant Code Examples
```terraform
resource "tencentcloud_cbs_storage" "encrytion_negative1" {
  storage_name      = "cbs-test"
  storage_type      = "CLOUD_SSD"
  storage_size      = 100
  availability_zone = "ap-guangzhou-3"
  encrypt           = true

  tags = {
    test = "tf"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "tencentcloud_cbs_storage" "encrytion_positive2" {
  storage_name      = "cbs-test"
  storage_type      = "CLOUD_SSD"
  storage_size      = 100
  availability_zone = "ap-guangzhou-3"
  encrypt           = false

  tags = {
    test = "tf"
  }
}

```

```terraform
resource "tencentcloud_cbs_storage" "encrytion_positive1" {
  storage_name      = "cbs-test"
  storage_type      = "CLOUD_SSD"
  storage_size      = 100
  availability_zone = "ap-guangzhou-3"

  tags = {
    test = "tf"
  }
}

```