---
title: "No ROS stack policy"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/no_ros_stack_policy"
  id: "72ceb736-0aee-43ea-a191-3a69ab135681"
  display_name: "No ROS stack policy"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Resource Management"
---
## Metadata

**Id:** `72ceb736-0aee-43ea-a191-3a69ab135681`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ros_stack)

### Description

A ROS stack should define a stack policy to protect resources from unintended changes during creation and update actions. Each `alicloud_ros_stack` resource must include either `stack_policy_body` or `stack_policy_url` for creation protection. For update protection, it must include either `stack_policy_during_update_body` or `stack_policy_during_update_url`. This rule reports a `MissingAttribute` issue when the corresponding attribute is not defined.

## Compliant Code Examples
```terraform
resource "alicloud_ros_stack" "neg2" {
  stack_name        = "tf-testaccstack"
  template_body     = <<EOF
    {
        "ROSTemplateFormatVersion": "2015-09-01"
    }
    EOF
  stack_policy_url = "oss://ros/stack-policy/demo"

  stack_policy_during_update_body = "oss://ros/stack-policy/demo"
}

```

```terraform
resource "alicloud_ros_stack" "neg1" {
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

  stack_policy_during_update_body = <<EOF
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
resource "alicloud_ros_stack" "pos2" {
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
resource "alicloud_ros_stack" "pos3" {
  stack_name        = "tf-testaccstack"
  template_body     = <<EOF
    {
        "ROSTemplateFormatVersion": "2015-09-01"
    }
    EOF
  stack_policy_during_update_body = <<EOF
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
resource "alicloud_ros_stack" "pos" {
  stack_name        = "tf-testaccstack"
  template_body     = <<EOF
    {
        "ROSTemplateFormatVersion": "2015-09-01"
    }
    EOF
}

```