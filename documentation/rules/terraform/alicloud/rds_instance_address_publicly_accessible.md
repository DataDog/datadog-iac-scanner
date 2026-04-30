---
title: "RDS DB instance publicly accessible"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/rds_instance_address_publicly_accessible"
  id: "terraform-alicloud-rds-db-instance-publicly-accessible"
  display_name: "RDS DB instance publicly accessible"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `terraform-alicloud-rds-db-instance-publicly-accessible`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Critical

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/db_instance#address)

### Description

Replace `0.0.0.0/0` with a specific CIDR range for `address`, or remove the public access entry to restrict connectivity.

## Compliant Code Examples
```terraform
resource "alicloud_db_instance" "example" {
  engine               = "MySQL"
  engine_version       = "5.6"
  instance_type        = "rds.mysql.s2.large"
  instance_storage     = "30"
  instance_charge_type = "Postpaid"
  instance_name        = var.name
  vswitch_id           = alicloud_vswitch.example.id
  monitoring_period    = "60"
}

```

```terraform
resource "alicloud_db_instance" "example" {
  engine               = "MySQL"
  engine_version       = "5.6"
  instance_type        = "rds.mysql.s2.large"
  instance_storage     = "30"
  instance_charge_type = "Postpaid"
  instance_name        = var.name
  vswitch_id           = alicloud_vswitch.example.id
  monitoring_period    = "60"
  address              = "10.23.12.24/24"
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_db_instance" "example" {
  engine               = "MySQL"
  engine_version       = "5.6"
  instance_type        = "rds.mysql.s2.large"
  instance_storage     = "30"
  instance_charge_type = "Postpaid"
  instance_name        = var.name
  vswitch_id           = alicloud_vswitch.example.id
  monitoring_period    = "60"
  address              = "0.0.0.0/0"
}

```