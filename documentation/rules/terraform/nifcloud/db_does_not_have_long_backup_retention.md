---
title: "NIFCLOUD RDB backup retention period below 7 days"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/db_does_not_have_long_backup_retention"
  id: "terraform-nifcloud-db-does-not-have-long-backup-retention"
  display_name: "NIFCLOUD RDB backup retention period below 7 days"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Backup"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-nifcloud-db-does-not-have-long-backup-retention{{< /copyable-code >}}

**Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Low

**Category:** Backup

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#backup_retention_period)

### Description

The RDB backup retention period is below 7 days. The `nifcloud_db_instance` resource must include the `backup_retention_period` attribute set to at least 7 (days). Resources missing this attribute or with a value less than 7 will be reported as `MissingAttribute` or `IncorrectValue`.

## Compliant Code Examples
```terraform
resource "nifcloud_db_instance" "negative" {
  identifier              = "example"
  instance_class          = "db.large8"
  backup_retention_period = 7
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