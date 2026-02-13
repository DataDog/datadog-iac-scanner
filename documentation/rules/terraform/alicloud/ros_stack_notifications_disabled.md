---
title: "ROS stack notifications disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ros_stack_notifications_disabled"
  id: "9ef08939-ea40-489c-8851-667870b2ef50"
  display_name: "ROS stack notifications disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `9ef08939-ea40-489c-8851-667870b2ef50`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ros_stack#notification_urls)

### Description

 The `alicloud_ros_stack` resource must include the `notification_urls` attribute with at least one URL to receive stack-related events. Without a defined, non-empty `notification_urls`, the stack will not receive lifecycle notifications such as create, update, or rollback.


## Compliant Code Examples
```terraform
resource "alicloud_ros_stack" "example" {
  stack_name        = "tf-testaccstack"
  notification_urls = ["oss://ros/stack-notification/demo"]
  template_body     = <<EOF
    {
        "ROSTemplateFormatVersion": "2015-09-01"
    }
    EOF
  stack_policy_body = <<EOF
    {
        "Statement": [{
            "Action": "Update:Delete",
            "Resource": "*",
            "Effect": "Allow",
            "Principal": "*"
        }]
    }
    EOF
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_ros_stack" "example" {
  stack_name        = "tf-testaccstack"
  template_body     = <<EOF
    {
        "ROSTemplateFormatVersion": "2015-09-01"
    }
    EOF
  stack_policy_body = <<EOF
    {
        "Statement": [{
            "Action": "Update:Delete",
            "Resource": "*",
            "Effect": "Allow",
            "Principal": "*"
        }]
    }
    EOF
}

```

```terraform
resource "alicloud_ros_stack" "example" {
  stack_name        = "tf-testaccstack"
  notification_urls = []
  template_body     = <<EOF
    {
        "ROSTemplateFormatVersion": "2015-09-01"
    }
    EOF
  stack_policy_body = <<EOF
    {
        "Statement": [{
            "Action": "Update:Delete",
            "Resource": "*",
            "Effect": "Allow",
            "Principal": "*"
        }]
    }
    EOF
}

```