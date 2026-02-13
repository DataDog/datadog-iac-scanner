---
title: "Beta - Nifcloud RDB has backup retention less than 2 days"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/db_does_not_have_long_backup_retention"
  id: "e5071f76-cbe7-468d-bb2b-d10f02d2b713"
  display_name: "Beta - Nifcloud RDB has backup retention less than 2 days"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** `e5071f76-cbe7-468d-bb2b-d10f02d2b713`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#backup_retention_period)

### Description

 The RDB backup retention period is less than 2 days. The `nifcloud_db_instance` resource must include the `backup_retention_period` attribute set to at least 2 (days). Resources missing this attribute or with a value less than 2 will be reported as `MissingAttribute` or `IncorrectValue`.


## Compliant Code Examples
```terraform
resource "nifcloud_db_instance" "negative" {
  identifier              = "example"
  instance_class          = "db.large8"
  backup_retention_period = 5
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_db_instance" "positive" {
  identifier              = "example"
  instance_class          = "db.large8"
  backup_retention_period = 1
}

```

```terraform
resource "nifcloud_db_instance" "positive" {
  identifier              = "example"
  instance_class          = "db.large8"
}

```