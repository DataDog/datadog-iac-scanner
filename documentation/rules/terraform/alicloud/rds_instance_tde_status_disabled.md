---
title: "RDS instance TDE status disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/rds_instance_tde_status_disabled"
  id: "44d434ca-a9bf-4203-8828-4c81a8d5a598"
  display_name: "RDS instance TDE status disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `44d434ca-a9bf-4203-8828-4c81a8d5a598`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/db_instance#tde_status)

### Description

 The `tde_status` parameter should be set to `Enabled` for supported RDS instances. This rule applies to `alicloud_db_instance` resources with `engine` set to `MySQL` (versions `5.6`, `5.7`, `8`) or `SQLServer` (versions `08r2_ent_ha`, `2012_ent_ha`, `2016_ent_ha`, `2017_ent`, `2019_std_ha`, `2019_ent`). It flags instances where `tde_status` is missing or set to `Disabled`. Set `tde_status = "Enabled"` to enforce Transparent Data Encryption (TDE).


## Compliant Code Examples
```terraform
resource "alicloud_db_instance" "default" {
    engine = "SQLServer"
    engine_version = "2019_std_ha"
    db_instance_class = "rds.mysql.t1.small"
    db_instance_storage = "10"
    tde_status = "Enabled"
    parameters = []
}

```

```terraform
resource "alicloud_db_instance" "default" {
    engine = "MySQL"
    engine_version = "8"
    db_instance_class = "rds.mysql.t1.small"
    db_instance_storage = "10"
    tde_status = "Enabled"
    parameters = [{
        name = "innodb_large_prefix"
        value = "ON"
    },{
        name = "connect_timeout"
        value = "50"
    }]
}

```

```terraform
resource "alicloud_db_instance" "default" {
    engine = "MySQL"
    engine_version = "5.6"
    db_instance_class = "rds.mysql.t1.small"
    db_instance_storage = "10"
    tde_status = "Enabled"
    parameters = [{
        name = "innodb_large_prefix"
        value = "ON"
    },{
        name = "connect_timeout"
        value = "50"
    }]
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_db_instance" "default" {
    engine = "MySQL"
    engine_version = "8"
    db_instance_class = "rds.mysql.t1.small"
    db_instance_storage = "10"
    parameters = [{
        name = "innodb_large_prefix"
        value = "ON"
    },{
        name = "connect_timeout"
        value = "50"
    }]
}

```

```terraform
resource "alicloud_db_instance" "default" {
    engine = "SQLServer"
    engine_version = "2019_std_ha"
    db_instance_class = "rds.mysql.t1.small"
    db_instance_storage = "10"
    tde_status = "Disabled"
    parameters = []
}

```

```terraform
resource "alicloud_db_instance" "default" {
    engine = "SQLServer"
    engine_version = "2016_ent_ha"
    db_instance_class = "rds.mysql.t1.small"
    db_instance_storage = "10"
    parameters = []
}

```