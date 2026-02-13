---
title: "Beta - Nifcloud RDB has public DB access"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/db_has_public_access"
  id: "fb387023-e4bb-42a8-9a70-6708aa7ff21b"
  display_name: "Beta - Nifcloud RDB has public DB access"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `fb387023-e4bb-42a8-9a70-6708aa7ff21b`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#publicly_accessible)

### Description

 The RDB instance is configured to allow public network access.
This rule detects `nifcloud_db_instance` resources where `publicly_accessible` is set to `true` and reports an `IncorrectValue` issue; network access should be limited to the minimum required for the application to function.
Report attributes: `documentId`, `resourceType`, `resourceName`, `searchKey`, `issueType`, `keyExpectedValue`, `keyActualValue`.


## Compliant Code Examples
```terraform
resource "nifcloud_db_instance" "negative" {
  identifier          = "example"
  instance_class      = "db.large8"
  publicly_accessible = false
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_db_instance" "positive" {
  identifier          = "example"
  instance_class      = "db.large8"
  publicly_accessible = true
}

```