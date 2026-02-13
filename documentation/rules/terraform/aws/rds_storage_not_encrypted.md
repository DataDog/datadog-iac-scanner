---
title: "RDS storage not encrypted"
group_id: "Terraform / AWS"
meta:
  name: "aws/rds_storage_not_encrypted"
  id: "3199c26c-7871-4cb3-99c2-10a59244ce7f"
  display_name: "RDS storage not encrypted"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `3199c26c-7871-4cb3-99c2-10a59244ce7f`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster#storage_encrypted)

### Description

 Amazon RDS storage encryption provides an additional layer of data protection by securing your data from unauthorized access to the underlying storage. When RDS storage is not encrypted, sensitive data stored in your databases could be exposed if the underlying storage is compromised. To properly secure your RDS clusters, set the `storage_encrypted` attribute to `true`, as shown in the secure example:

```terraform
resource "aws_rds_cluster" "example" {
  // other configuration...
  storage_encrypted = true
}
```

Without this setting, your database is vulnerable to data exposure if physical storage media is stolen or improperly decommissioned.


## Compliant Code Examples
```terraform
resource "aws_rds_cluster" "negative2" {
  cluster_identifier  = "cloudrail-test-non-encrypted"
  engine              = "aurora-mysql"
  engine_version      = "5.7.mysql_aurora.2.03.2"
  engine_mode         = "serverless"
  availability_zones  = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
  database_name       = "cloudrail"
  master_username     = "administrator"
  master_password     = "cloudrail-TEST-password"
  skip_final_snapshot = true
}

```

```terraform
resource "aws_rds_cluster" "negative1" {
  cluster_identifier  = "cloudrail-test-non-encrypted"
  engine              = "aurora-mysql"
  engine_version      = "5.7.mysql_aurora.2.03.2"
  availability_zones  = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
  database_name       = "cloudrail"
  master_username     = "administrator"
  master_password     = "cloudrail-TEST-password"
  skip_final_snapshot = true
  storage_encrypted   = true
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_rds_cluster" "positive3" {
  cluster_identifier  = "cloudrail-test-non-encrypted"
  engine              = "aurora-mysql"
  engine_version      = "5.7.mysql_aurora.2.03.2"
  availability_zones  = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
  database_name       = "cloudrail"
  master_username     = "administrator"
  master_password     = "cloudrail-TEST-password"
  skip_final_snapshot = true
  storage_encrypted   = false
}

```

```terraform
resource "aws_rds_cluster" "positive1" {
  cluster_identifier      = "aurora-cluster-demo"
  engine                  = "aurora-mysql"
  engine_version          = "5.7.mysql_aurora.2.03.2"
  availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
  database_name           = "mydb"
  master_username         = "foo"
  master_password         = "bar"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
}

```