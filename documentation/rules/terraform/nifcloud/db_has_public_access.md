---
title: "NIFCLOUD RDB has public DB access"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/db_has_public_access"
  id: "terraform-nifcloud-db-has-public-access"
  display_name: "NIFCLOUD RDB has public DB access"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-nifcloud-db-has-public-access{{< /copyable-code >}}

**Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

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