---
title: "ROS stack without template"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ros_stack_without_template"
  id: "92d65c51-5d82-4507-a2a1-d252e9706855"
  display_name: "ROS stack without template"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Build Process"
---
## Metadata

**Id:** `92d65c51-5d82-4507-a2a1-d252e9706855`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ros_stack)

### Description

 An `alicloud_ros_stack` resource must define a template using either the `template_url` or `template_body` attribute. At least one of these must be present to describe the stack template. If both are missing, the rule reports a `MissingAttribute` issue indicating that one of the two must be set. This ensures ROS has a template to provision resources.


## Compliant Code Examples
```terraform
resource "alicloud_ros_stack" "example1" {
  stack_name        = "tf-testaccstack1"
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