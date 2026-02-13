---
title: "DocumentDB logging is disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/docdb_logging_disabled"
  id: "56f6a008-1b14-4af4-b9b2-ab7cf7e27641"
  display_name: "DocumentDB logging is disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `56f6a008-1b14-4af4-b9b2-ab7cf7e27641`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/docdb_cluster#enabled_cloudwatch_logs_exports)

### Description

 Enabling logging for Amazon DocumentDB clusters helps ensure that database activity is captured and monitored, allowing for the detection of anomalous behavior and aiding in incident investigations. If logging is not enabled by omitting the `enabled_cloudwatch_logs_exports` attribute, critical events and queries may go unrecorded, making it difficult to audit access or troubleshoot security events. To enforce secure configurations, the `aws_docdb_cluster` resource should specify the desired log exports, such as in the example below:

```
resource "aws_docdb_cluster" "example" {
  cluster_identifier      = "my-docdb-cluster"
  engine                  = "docdb"
  master_username         = "foo"
  master_password         = "mustbeeightchars"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true

  enabled_cloudwatch_logs_exports = ["profiler", "audit"]
}
```


## Compliant Code Examples
```terraform
resource "aws_docdb_cluster" "negative1" {
  cluster_identifier      = "my-docdb-cluster"
  engine                  = "docdb"
  master_username         = "foo"
  master_password         = "mustbeeightchars"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true

  enabled_cloudwatch_logs_exports = ["profiler", "audit"]
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_docdb_cluster" "positive2" {
  cluster_identifier      = "my-docdb-cluster"
  engine                  = "docdb"
  master_username         = "foo"
  master_password         = "mustbeeightchars"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true

  enabled_cloudwatch_logs_exports = []
}

```

```terraform
resource "aws_docdb_cluster" "positive3" {
  cluster_identifier      = "my-docdb-cluster"
  engine                  = "docdb"
  master_username         = "foo"
  master_password         = "mustbeeightchars"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true

  enabled_cloudwatch_logs_exports = ["profiler"]
}

```

```terraform
resource "aws_docdb_cluster" "positive4" {
  cluster_identifier      = "my-docdb-cluster"
  engine                  = "docdb"
  master_username         = "foo"
  master_password         = "mustbeeightchars"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true

  enabled_cloudwatch_logs_exports = ["audit"]
}

```