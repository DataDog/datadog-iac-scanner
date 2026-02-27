---
title: "Beta - CDB instance without backup policy"
group_id: "Terraform / TencentCloud"
meta:
  name: "tencentcloud/cdb_instance_without_backup_policy"
  id: "ca94be07-7de3-4ae7-85ef-67e0462ec694"
  display_name: "Beta - CDB instance without backup policy"
  cloud_provider: "TencentCloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** `ca94be07-7de3-4ae7-85ef-67e0462ec694`

**Cloud Provider:** TencentCloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/tencentcloudstack/tencentcloud/latest/docs/resources/mysql_backup_policy)

### Description

A CDB instance should include a `tencentcloud_mysql_backup_policy`. This rule verifies that each `tencentcloud_mysql_instance` has a matching `tencentcloud_mysql_backup_policy` whose `mysql_id` references the instance name. Instances without a matching backup policy are reported as `MissingAttribute`.

## Compliant Code Examples
```terraform
data "tencentcloud_availability_zones_by_product" "zones" {
  product = "cdb"
}

resource "tencentcloud_vpc" "vpc" {
  name       = "vpc-mysql"
  cidr_block = "10.0.0.0/16"
}

resource "tencentcloud_subnet" "subnet" {
  availability_zone = data.tencentcloud_availability_zones_by_product.zones.zones.0.name
  name              = "subnet-mysql"
  vpc_id            = tencentcloud_vpc.vpc.id
  cidr_block        = "10.0.0.0/16"
  is_multicast      = false
}

resource "tencentcloud_security_group" "security_group" {
  name        = "sg-mysql"
  description = "mysql test"
}

resource "tencentcloud_mysql_instance" "has_backup_policy" {
  engine_version    = "5.7"
  charge_type       = "POSTPAID"
  slave_deploy_mode = 0
  availability_zone = data.tencentcloud_availability_zones_by_product.zones.zones.0.name
  slave_sync_mode   = 1
  instance_name     = "tf-example-mysql"
  mem_size          = 4000
  volume_size       = 200
  vpc_id            = tencentcloud_vpc.vpc.id
  subnet_id         = tencentcloud_subnet.subnet.id
  intranet_port     = 3306
  security_groups   = [tencentcloud_security_group.security_group.id]

  tags = {
    name = "test"
  }

  parameters = {
    character_set_server = "utf8"
    max_connections      = "1000"
  }
}

resource "tencentcloud_mysql_backup_policy" "example" {
  mysql_id              = tencentcloud_mysql_instance.has_backup_policy.id
  retention_period      = 7
  backup_model          = "physical"
  backup_time           = "22:00-02:00"
  binlog_period         = 32
  enable_binlog_standby = "off"
  binlog_standby_days   = 31
}

```
## Non-Compliant Code Examples
```terraform
data "tencentcloud_availability_zones_by_product" "zones" {
  product = "cdb"
}

resource "tencentcloud_vpc" "vpc" {
  name       = "vpc-mysql"
  cidr_block = "10.0.0.0/16"
}

resource "tencentcloud_subnet" "subnet" {
  availability_zone = data.tencentcloud_availability_zones_by_product.zones.zones.0.name
  name              = "subnet-mysql"
  vpc_id            = tencentcloud_vpc.vpc.id
  cidr_block        = "10.0.0.0/16"
  is_multicast      = false
}

resource "tencentcloud_security_group" "security_group" {
  name        = "sg-mysql"
  description = "mysql test"
}

resource "tencentcloud_mysql_instance" "none_backup_policy" {
  engine_version    = "5.7"
  charge_type       = "POSTPAID"
  slave_deploy_mode = 0
  availability_zone = data.tencentcloud_availability_zones_by_product.zones.zones.0.name
  slave_sync_mode   = 1
  instance_name     = "tf-example-mysql"
  mem_size          = 4000
  volume_size       = 200
  vpc_id            = tencentcloud_vpc.vpc.id
  subnet_id         = tencentcloud_subnet.subnet.id
  intranet_port     = 3306
  security_groups   = [tencentcloud_security_group.security_group.id]

  tags = {
    name = "test"
  }

  parameters = {
    character_set_server = "utf8"
    max_connections      = "1000"
  }
}

```