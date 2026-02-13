---
title: "RDS instance log disconnections disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/rds_instance_log_disconnections_disabled"
  id: "d53f4123-f8d8-4224-8cb3-f920b151cc98"
  display_name: "RDS instance log disconnections disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `d53f4123-f8d8-4224-8cb3-f920b151cc98`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/db_instance#parameters)

### Description

The `log_disconnections` parameter must be set to `ON` for RDS instances. The rule inspects `alicloud_db_instance` resources and their `parameters` array for an entry where `name` is `log_disconnections` and `value` is `ON`.

If the parameter exists with `value = OFF`, the policy reports an `IncorrectValue` issue. If the `parameters` array is missing or the parameter is absent, the policy reports a `MissingAttribute` issue and suggests adding or updating the entry to set `value = ON` (for example, `parameters = [{ name = "log_disconnections", value = "ON" }]`).

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
        name = "log_disconnections"
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
    parameters = [
        {
            name = "innodb_large_prefix"
            value = "ON"
        },{
            name = "connect_timeout"
            value = "50"
        },{
            name = "log_disconnections"
            value = "OFF"
        }
    ]
}

```