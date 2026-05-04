---
title: "NIFCLOUD NAS undefined description to NAS security group"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/nas_security_group_description_undefined"
  id: "terraform-nifcloud-nas-security-group-description-undefined"
  display_name: "NIFCLOUD NAS undefined description to NAS security group"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `terraform-nifcloud-nas-security-group-description-undefined`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/nas_security_group#description)

### Description

Missing description for `nifcloud_nas_security_group`.
Detects `nifcloud_nas_security_group` resources that do not include the `description` attribute.
A `description` is required for auditing and inventory purposes; provide a meaningful `description` to clarify the resource's purpose.

## Compliant Code Examples
```terraform
resource "nifcloud_nas_security_group" "negative" {
  group_name  = "app"
  description = "Allow from app traffic"
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_nas_security_group" "positive" {
  group_name  = "app"
}

```