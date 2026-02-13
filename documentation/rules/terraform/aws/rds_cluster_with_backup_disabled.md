---
title: "RDS cluster with backup disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/rds_cluster_with_backup_disabled"
  id: "e542bd46-58c4-4e0f-a52a-1fb4f9548e02"
  display_name: "RDS cluster with backup disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** `e542bd46-58c4-4e0f-a52a-1fb4f9548e02`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster#backup_retention_period)

### Description

 RDS cluster backup retention period should be explicitly defined. When creating an AWS RDS cluster using Terraform, omitting the `backup_retention_period` parameter allows the database to default to the minimum backup retention, which could be zero or just one day depending on the engine. This short or undefined retention window risks losing the ability to restore data to a specific point in time, potentially resulting in irreversible data loss in the event of accidental deletion, corruption, or ransomware attacks. Explicitly setting a sufficient retention period ensures backups are available for recovery as required by business continuity or compliance requirements.


## Compliant Code Examples
```terraform
resource "aws_rds_cluster" "postgresql" {
  cluster_identifier      = "aurora-cluster-demo"
  engine                  = "aurora-postgresql"
  availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
  database_name           = "mydb"
  master_username         = "foo"
  master_password         = "bar"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_rds_cluster" "postgresql" {
  cluster_identifier      = "aurora-cluster-demo"
  engine                  = "aurora-postgresql"
  availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
  database_name           = "mydb"
  master_username         = "foo"
  master_password         = "bar"
  preferred_backup_window = "07:00-09:00"
}


```