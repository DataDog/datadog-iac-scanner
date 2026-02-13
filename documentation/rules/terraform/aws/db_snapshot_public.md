---
title: "DB snapshot is public"
group_id: "Terraform / AWS"
meta:
  name: "aws/db_snapshot_public"
  id: "f0d8781f-1991-4958-9917-d39283b168a0"
  display_name: "DB snapshot is public"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `f0d8781f-1991-4958-9917-d39283b168a0`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_snapshot#shared_accounts-1)

### Description

 AWS DB Snapshots contain a complete copy of your database, including all its data structures, stored procedures, and sensitive information. When a DB snapshot is made public by setting `shared_accounts` to include `all`, anyone with an AWS account can access and restore your database, potentially exposing confidential data or intellectual property. To mitigate this risk, always keep your DB snapshots private by ensuring the `shared_accounts` attribute is either not specified or set to an empty array. Compare the secure configuration (`shared_accounts = []`) with the vulnerable configuration (`shared_accounts = ["all"]`). Implementing proper access controls for DB snapshots is essential for protecting sensitive data and maintaining compliance with data protection regulations.


## Compliant Code Examples
```terraform
resource "aws_db_snapshot" "private_snapshot" {
  db_snapshot_identifier = "private-db-snapshot"
  db_instance_identifier = "my-db-instance"
}

```

```terraform
resource "aws_db_snapshot" "private_snapshot" {
  db_snapshot_identifier = "private-db-snapshot"
  db_instance_identifier = "my-db-instance"
  shared_accounts        = []
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_db_snapshot" "public_snapshot" {
  db_snapshot_identifier = "public-db-snapshot"
  db_instance_identifier = "my-db-instance"
  shared_accounts        = ["all"]
}

```