---
title: "ECS data disk KMS key ID undefined"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ecs_data_disk_kms_key_id_undefined"
  id: "f262118c-1ac6-4bb3-8495-cc48f1775b85"
  display_name: "ECS data disk KMS key ID undefined"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `f262118c-1ac6-4bb3-8495-cc48f1775b85`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/disk#kms_key_id)

### Description

ECS data disks must have the `kms_key_id` attribute set. This rule flags any `alicloud_disk` resource missing the `kms_key_id` attribute.
Setting this ensures disks are encrypted using a KMS key and avoids unencrypted storage.

## Compliant Code Examples
```terraform
# Create a new ECS disk.
resource "alicloud_disk" "ecs_disk" {
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
# Create a new ECS disk.
resource "alicloud_disk" "ecs_disk" {
  # cn-beijing
  availability_zone = "cn-beijing-b"
  name              = "New-disk"
  description       = "Hello ecs disk."
  category          = "cloud_efficiency"
  size              = "30"
  encrypted         = true
  tags = {
    Name = "TerraformTest"
  }
}

```