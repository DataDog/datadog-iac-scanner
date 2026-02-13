---
title: "Beta - Nifcloud RDB undefined description to DB security group"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/db_security_group_description_undefined"
  id: "940ddce2-26bd-4e31-a9b4-382714f73231"
  display_name: "Beta - Nifcloud RDB undefined description to DB security group"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `940ddce2-26bd-4e31-a9b4-382714f73231`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_security_group#description)

### Description

 Missing description for DB security group.

Resources of type `nifcloud_db_security_group` should include a `description` attribute for auditing and identification. This rule flags `nifcloud_db_security_group` resources that do not define a `description`.


## Compliant Code Examples
```terraform
resource "nifcloud_db_security_group" "negative" {
  group_name        = "example"
  availability_zone = "east-11"
  description       = "Allow from app traffic"
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_db_security_group" "positive" {
  group_name        = "example"
  availability_zone = "east-11"
}

```