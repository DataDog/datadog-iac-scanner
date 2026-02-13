---
title: "Neptune database cluster encryption disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/neptune_database_cluster_encryption_disabled"
  id: "98d59056-f745-4ef5-8613-32bca8d40b7e"
  display_name: "Neptune database cluster encryption disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `98d59056-f745-4ef5-8613-32bca8d40b7e`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster#storage_encrypted)

### Description

 Amazon Neptune is a fully managed graph database service that makes it easy to build and run applications working with highly connected datasets. When Neptune database cluster storage encryption is disabled, sensitive data stored in these clusters is vulnerable to unauthorized access if the underlying storage is compromised. Without encryption, data is stored in plaintext, posing a significant security risk.

To properly secure Neptune clusters, always set the `storage_encrypted parameter` to true, as shown in this example: `storage_encrypted = true`. Avoid configurations that either omit this parameter or explicitly set it to `false`.


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
  iam_database_authentication_enabled = true
  apply_immediately                   = true
}

resource "aws_neptune_cluster" "positive2" {
  cluster_identifier                  = "neptune-cluster-demo"
  engine                              = "neptune"
  backup_retention_period             = 5
  preferred_backup_window             = "07:00-09:00"
  skip_final_snapshot                 = true
  iam_database_authentication_enabled = true
  apply_immediately                   = true
  storage_encrypted                   = false
}
```