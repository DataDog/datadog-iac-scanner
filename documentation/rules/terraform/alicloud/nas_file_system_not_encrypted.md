---
title: "NAS file system not encrypted"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/nas_file_system_not_encrypted"
  id: "67bfdff1-31ce-4525-b564-e94368735360"
  display_name: "NAS file system not encrypted"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `67bfdff1-31ce-4525-b564-e94368735360`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/nas_file_system#encrypt_type)

### Description

NAS file systems must be encrypted. The `alicloud_nas_file_system` resource must include the `encrypt_type` attribute, and it must not be set to `0`. To remediate, set `encrypt_type` to `"2"` to enable user-managed KMS encryption.

## Compliant Code Examples
```terraform
resource "alicloud_nas_file_system" "foo2" {
  protocol_type = "NFS"
  storage_type  = "Performance"
  description   = "tf-testAccNasConfig"
  encrypt_type  = "2"
}

```

```terraform
resource "alicloud_nas_file_system" "foo" {
  protocol_type = "NFS"
  storage_type  = "Performance"
  description   = "tf-testAccNasConfig"
  encrypt_type  = "1"
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_nas_file_system" "foopos2" {
  protocol_type = "NFS"
  storage_type  = "Performance"
  description   = "tf-testAccNasConfig"
}

```

```terraform
resource "alicloud_nas_file_system" "foopos" {
  protocol_type = "NFS"
  storage_type  = "Performance"
  description   = "tf-testAccNasConfig"
  encrypt_type  = "0"
}

```