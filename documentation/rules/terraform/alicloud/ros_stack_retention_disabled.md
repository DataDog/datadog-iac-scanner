---
title: "ROS stack retention disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ros_stack_retention_disabled"
  id: "4bb06fa1-2114-4a00-b7b5-6aeab8b896f0"
  display_name: "ROS stack retention disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** `4bb06fa1-2114-4a00-b7b5-6aeab8b896f0`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ros_stack_instance#retain_stacks)

### Description

 The `retain_stacks` attribute should be enabled to preserve the stack when deleting a stack instance from a stack group.
If `retain_stacks` is undefined or set to `false`, the underlying `alicloud_ros_stack_instance` is deleted when the instance is removed. Set `retain_stacks = true` to retain the stack.


## Compliant Code Examples
```terraform
resource "alicloud_ros_stack_instance" "example" {
  stack_group_name          = alicloud_ros_stack_group.example.stack_group_name
  stack_instance_account_id = "example_value"
  stack_instance_region_id  = data.alicloud_ros_regions.example.regions.0.region_id
  operation_preferences     = "{\"FailureToleranceCount\": 1, \"MaxConcurrentCount\": 2}"
  retain_stacks             = true
  parameter_overrides {
    parameter_value = "VpcName"
    parameter_key   = "VpcName"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_ros_stack_instance" "example" {
  stack_group_name          = alicloud_ros_stack_group.example.stack_group_name
  stack_instance_account_id = "example_value"
  stack_instance_region_id  = data.alicloud_ros_regions.example.regions.0.region_id
  operation_preferences     = "{\"FailureToleranceCount\": 1, \"MaxConcurrentCount\": 2}"
  parameter_overrides {
    parameter_value = "VpcName"
    parameter_key   = "VpcName"
  }
}

```

```terraform
resource "alicloud_ros_stack_instance" "example" {
  stack_group_name          = alicloud_ros_stack_group.example.stack_group_name
  stack_instance_account_id = "example_value"
  stack_instance_region_id  = data.alicloud_ros_regions.example.regions.0.region_id
  operation_preferences     = "{\"FailureToleranceCount\": 1, \"MaxConcurrentCount\": 2}"
  retain_stacks             = false
  parameter_overrides {
    parameter_value = "VpcName"
    parameter_key   = "VpcName"
  }
}

```