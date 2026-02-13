---
title: "RDS instance log duration disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/rds_instance_log_duration_disabled"
  id: "a597e05a-c065-44e7-9cc8-742f572a504a"
  display_name: "RDS instance log duration disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `a597e05a-c065-44e7-9cc8-742f572a504a`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/db_instance#parameters)

### Description

 The `log_duration` parameter must be defined in the `parameters` array of `alicloud_db_instance` resources and set to `ON`.  
If `log_duration` exists and is set to `OFF`, the rule reports an `IncorrectValue` issue and suggests replacing `OFF` with `ON`.  
If the `parameters` array or the `log_duration` parameter is missing, the rule reports a `MissingAttribute` issue and suggests adding `parameters = [{ name = "log_duration" value = "ON" }]`.


## Compliant Code Examples
```terraform
resource "alicloud_db_instance" "default" {
    engine = "MySQL"
    engine_version = "5.6"
    db_instance_class = "rds.mysql.t1.small"
    db_instance_storage = "10"
    parameters = [{
        name = "innodb_large_prefix"
        value = "ON"
    },{
        name = "connect_timeout"
        value = "50"
    },{
        name = "log_duration"
        value = "ON"
    }]
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_db_instance" "default" {
    engine = "MySQL"
    engine_version = "5.6"
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
    engine = "MySQL"
    engine_version = "5.6"
    db_instance_class = "rds.mysql.t1.small"
    db_instance_storage = "10"
}

```

```terraform
resource "alicloud_db_instance" "default" {
    engine = "MySQL"
    engine_version = "5.6"
    db_instance_class = "rds.mysql.t1.small"
    db_instance_storage = "10"
    parameters = [{
        name = "innodb_large_prefix"
        value = "ON"
    },{
        name = "connect_timeout"
        value = "50"
    },{
        name = "log_duration"
        value = "OFF"
    }]
}

```