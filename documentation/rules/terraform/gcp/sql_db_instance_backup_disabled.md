---
title: "SQL DB instance backup disabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/sql_db_instance_backup_disabled"
  id: "cf3c7631-cd1e-42f3-8801-a561214a6e79"
  display_name: "SQL DB instance backup disabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** `cf3c7631-cd1e-42f3-8801-a561214a6e79`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance)

### Description

This check verifies whether automated backups are enabled for all Google Cloud SQL database instances by ensuring the `backup_configuration` block has the `enabled = true` attribute. If automated backups are disabled or the `backup_configuration` block is missing, databases are at risk of unrecoverable data loss in the event of accidental deletion, corruption, or other failures. When automated backups are disabled, the configuration appears as follows:

```
settings {
    backup_configuration {
        enabled = false
    }
}
```

To mitigate this risk, ensure backups are enabled using the following configuration:

```
settings {
    backup_configuration {
        enabled = true
    }
}
```

This ensures that point-in-time recovery is possible and critical business data can be restored when needed.

## Compliant Code Examples
```terraform
resource "google_sql_database_instance" "negative1" {
    name             = "master-instance"
    database_version = "POSTGRES_11"
    region           = "us-central1"
 
    settings {
        backup_configuration{
            enabled = true
        }
    }
}

```
## Non-Compliant Code Examples
```terraform
resource "google_sql_database_instance" "positive1" {
    name             = "master-instance"
    database_version = "POSTGRES_11"
    region           = "us-central1"

    settings {
        tier = "db-f1-micro"
    }
}

resource "google_sql_database_instance" "positive2" {
    name             = "master-instance"
    database_version = "POSTGRES_11"
    region           = "us-central1"

    settings {
        tier = "db-f1-micro"
        backup_configuration{
            binary_log_enabled = true
        }
    }
}

resource "google_sql_database_instance" "positive3" {
    name             = "master-instance"
    database_version = "POSTGRES_11"
    region           = "us-central1"

    settings {
        backup_configuration{
            enabled = false
        }
    }
}


```