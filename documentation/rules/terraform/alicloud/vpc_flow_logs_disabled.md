---
title: "VPC flow logs disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/vpc_flow_logs_disabled"
  id: "d2731f3d-a992-44ed-812e-f4f1c2747d71"
  display_name: "VPC flow logs disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `d2731f3d-a992-44ed-812e-f4f1c2747d71`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/vpc_flow_log)

### Description

 Every `alicloud_vpc` resource should have an associated `alicloud_vpc_flow_log`. If a VPC lacks a flow log, the rule reports an `IncorrectValue` issue on the `alicloud_vpc` resource. Requiring `alicloud_vpc_flow_log` ensures VPC network traffic is captured for auditing and troubleshooting.


## Compliant Code Examples
```terraform
resource "alicloud_vpc" "main" {
  cidr_block = "192.168.0.0/24"
  name       = var.name
}

resource "alicloud_vpc_flow_log" "default" {
  depends_on     = ["alicloud_vpc.main"]
  resource_id    = alicloud_vpc.main.id
  resource_type  = "VPC"
  traffic_type   = "All"
  log_store_name = var.log_store_name
  project_name   = var.project_name
  flow_log_name  = var.name
  status         = "Active"
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_vpc" "main" {
  cidr_block = "192.168.0.0/24"
  name       = var.name
}

resource "alicloud_vpc_flow_log" "default" {
  depends_on     = ["alicloud_vpc.default"]
  resource_id    = alicloud_vpc.default.id
  resource_type  = "VPC"
  traffic_type   = "All"
  log_store_name = var.log_store_name
  project_name   = var.project_name
  flow_log_name  = var.name
  status         = "Active"
}

```