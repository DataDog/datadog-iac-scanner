---
title: "Beta - Nifcloud NAS undefined description to NAS security group"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/nas_security_group_description_undefined"
  id: "e840c54a-7a4c-405f-b8c1-c49a54b87d11"
  display_name: "Beta - Nifcloud NAS undefined description to NAS security group"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `e840c54a-7a4c-405f-b8c1-c49a54b87d11`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

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