---
title: "RDS DB instance publicly accessible"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/rds_instance_publicly_accessible"
  id: "1b4565c0-4877-49ac-ab03-adebbccd42ae"
  display_name: "RDS DB instance publicly accessible"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `1b4565c0-4877-49ac-ab03-adebbccd42ae`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/db_instance#security_ips)

### Description

`0.0.0.0` or `0.0.0.0/0` should not be included in the `security_ips` list. This rule flags `alicloud_db_instance` resources whose `security_ips` contain these public addresses. Allowing them grants public network access to the database instance and may expose it to the internet.

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
    }]
}

```

```terraform
resource "alicloud_db_instance" "default" {
    engine = "MySQL"
    engine_version = "5.6"
    db_instance_class = "rds.mysql.t1.small"
    db_instance_storage = "10"
    security_ips = [
        "10.23.12.24"
        ]
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
    engine_version = "5.6"
    db_instance_class = "rds.mysql.t1.small"
    db_instance_storage = "10"
    security_ips = [
        "0.0.0.0/0",
        "10.23.12.24/24",
    ]
    parameters = [
        {
            name = "innodb_large_prefix"
            value = "ON"
        },{
            name = "connect_timeout"
            value = "50"
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
    security_ips = [
        "0.0.0.0",
        "10.23.12.24/24"
    ]
    parameters = [
        {
            name = "innodb_large_prefix"
            value = "ON"
        },{
            name = "connect_timeout"
            value = "50"
        }
    ]
}

```