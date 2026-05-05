---
title: "Neptune cluster with IAM database authentication disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/neptune_cluster_with_iam_database_authentication_disabled"
  id: "terraform-aws-neptune-cluster-with-iam-database-authentication-disabled"
  display_name: "Neptune cluster with IAM database authentication disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `terraform-aws-neptune-cluster-with-iam-database-authentication-disabled`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster#storage_encrypted)

### Description

AWS Neptune clusters should have IAM database authentication enabled to enhance security by using IAM users and roles instead of standard username and password credentials. When disabled, an attacker who gains access to the database credentials could directly connect to the database without additional IAM verification. To secure your Neptune cluster, add the `iam_database_authentication_enabled = true` parameter, as shown in the following example:

```terraform
resource "aws_neptune_cluster" "example" {
  cluster_identifier = "neptune-cluster-demo"
  // other configuration...
  iam_database_authentication_enabled = true
}
```

## Compliant Code Examples
```terraform
resource "aws_neptune_cluster" "negative1" {
  cluster_identifier                  = "neptune-cluster-demo"
  engine                              = "neptune"
  backup_retention_period             = 5
  preferred_backup_window             = "07:00-09:00"
  skip_final_snapshot                 = true
  iam_database_authentication_enabled = true
  apply_immediately                   = true
  storage_encrypted                   = true
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_neptune_cluster" "positive1" {
  cluster_identifier                  = "neptune-cluster-demo"
  engine                              = "neptune"
  backup_retention_period             = 5
  preferred_backup_window             = "07:00-09:00"
  skip_final_snapshot                 = true
  apply_immediately                   = true
  storage_encrypted                   = true
}

resource "aws_neptune_cluster" "positive2" {
  cluster_identifier                  = "neptune-cluster-demo"
  engine                              = "neptune"
  backup_retention_period             = 5
  preferred_backup_window             = "07:00-09:00"
  skip_final_snapshot                 = true
  iam_database_authentication_enabled = false
  apply_immediately                   = true
  storage_encrypted                   = true
}

```