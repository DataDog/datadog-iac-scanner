---
title: "Beta - CLB instance log setting disabled"
group_id: "Terraform / TencentCloud"
meta:
  name: "tencentcloud/clb_instance_log_setting_disabled"
  id: "ada01ed1-b10c-4f2a-b110-b20fa4f9baa6"
  display_name: "Beta - CLB instance log setting disabled"
  cloud_provider: "TencentCloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `ada01ed1-b10c-4f2a-b110-b20fa4f9baa6`

**Cloud Provider:** TencentCloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/tencentcloudstack/tencentcloud/latest/docs/resources/clb_instance#log_set_id)

### Description

CLB instance should have logging enabled.

This rule checks that the `tencentcloud_clb_instance` resource sets both `log_set_id` and `log_topic_id`. If either attribute is missing, the rule reports a `MissingAttribute` issue indicating that `log_set_id` and `log_topic_id` are not set. Enabling these attributes ensures CLB access logs are collected.

## Compliant Code Examples
```terraform
resource "tencentcloud_vpc" "vpc_test" {
  name       = "clb-test"
  cidr_block = "10.0.0.0/16"
}

resource "tencentcloud_route_table" "rtb_test" {
  name   = "clb-test"
  vpc_id = tencentcloud_vpc.vpc_test.id
}

resource "tencentcloud_subnet" "subnet_test" {
  name              = "clb-test"
  cidr_block        = "10.0.1.0/24"
  availability_zone = "ap-guangzhou-3"
  vpc_id            = tencentcloud_vpc.vpc_test.id
  route_table_id    = tencentcloud_route_table.rtb_test.id
}

resource "tencentcloud_clb_log_set" "set" {
  period = 7
}

resource "tencentcloud_clb_log_topic" "topic" {
  log_set_id = tencentcloud_clb_log_set.set.id
  topic_name = "clb-topic"
}

resource "tencentcloud_clb_instance" "internal_clb" {
  network_type                 = "INTERNAL"
  clb_name                     = "clb_example"
  project_id                   = 0
  vpc_id                       = tencentcloud_vpc.vpc_test.id
  subnet_id                    = tencentcloud_subnet.subnet_test.id
  load_balancer_pass_to_target = true
  log_set_id                   = tencentcloud_clb_log_set.set.id
  log_topic_id                 = tencentcloud_clb_log_topic.topic.id

  tags = {
    test = "tf"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "tencentcloud_vpc" "vpc_test" {
  name       = "clb-test"
  cidr_block = "10.0.0.0/16"
}

resource "tencentcloud_route_table" "rtb_test" {
  name   = "clb-test"
  vpc_id = tencentcloud_vpc.vpc_test.id
}

resource "tencentcloud_subnet" "subnet_test" {
  name              = "clb-test"
  cidr_block        = "10.0.1.0/24"
  availability_zone = "ap-guangzhou-3"
  vpc_id            = tencentcloud_vpc.vpc_test.id
  route_table_id    = tencentcloud_route_table.rtb_test.id
}

resource "tencentcloud_clb_instance" "internal_clb" {
  network_type                 = "INTERNAL"
  clb_name                     = "clb_example"
  project_id                   = 0
  vpc_id                       = tencentcloud_vpc.vpc_test.id
  subnet_id                    = tencentcloud_subnet.subnet_test.id
  load_balancer_pass_to_target = true

  tags = {
    test = "tf"
  }
}

```