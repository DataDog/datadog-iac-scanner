---
title: "RDS instance log connections disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/rds_instance_log_connections_disabled"
  id: "terraform-alicloud-rds-instance-log-connections-disabled"
  display_name: "RDS instance log connections disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `terraform-alicloud-rds-instance-log-connections-disabled`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/db_instance#parameters)

### Description

The `log_connections` parameter should be set to `ON` for RDS instances. This rule flags `alicloud_db_instance` resources when the `parameters` array does not include a `log_connections` entry or when `value = "OFF"`. Remediation is to add or replace the `parameters` entry with `name = "log_connections"` and `value = "ON"`.

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
        name = "log_connections"
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
    parameters = [
        {
            name = "innodb_large_prefix"
            value = "ON"
        },{
            name = "connect_timeout"
            value = "50"
        },{
            name = "log_connections"
            value = "OFF"
        }
    ]
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
    }]
}

```