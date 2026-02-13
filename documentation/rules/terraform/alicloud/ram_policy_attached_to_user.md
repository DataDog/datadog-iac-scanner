---
title: "RAM policy attached to user"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ram_policy_attached_to_user"
  id: "66505003-7aba-45a1-8d83-5162d5706ef5"
  display_name: "RAM policy attached to user"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `66505003-7aba-45a1-8d83-5162d5706ef5`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_user_policy_attachment)

### Description

 RAM policies should not be attached directly to users. The Terraform resource `alicloud_ram_user_policy_attachment` must be `undefined` or omitted from the configuration. This rule flags any `alicloud_ram_user_policy_attachment` defined for users as incorrect.


## Compliant Code Examples
```terraform
# Create a RAM Role Policy attachment.
resource "alicloud_ram_role" "role3" {
  name        = "roleName"
  document    = <<EOF
    {
      "Statement": [
        {
          "Action": "sts:AssumeRole",
          "Effect": "Allow",
          "Principal": {
            "Service": [
              "apigateway.aliyuncs.com", 
              "ecs.aliyuncs.com"
            ]
          }
        }
      ],
      "Version": "1"
    }
    EOF
  description = "this is a role test."
  force       = true
}

resource "alicloud_ram_policy" "policy3" {
  name        = "policyName"
  document    = <<EOF
  {
    "Statement": [
      {
        "Action": [
          "oss:ListObjects",
          "oss:GetObject"
        ],
        "Effect": "Allow",
        "Resource": [
          "acs:oss:*:*:mybucket",
          "acs:oss:*:*:mybucket/*"
        ]
      }
    ],
      "Version": "1"
  }
  EOF
  description = "this is a policy test"
  force       = true
}

resource "alicloud_ram_role_policy_attachment" "attach" {
  policy_name = alicloud_ram_policy.policy3.name
  policy_type = alicloud_ram_policy.policy3.type
  role_name   = alicloud_ram_role.role3.name
}

```

```terraform
# Create a RAM Group Policy attachment.
resource "alicloud_ram_group" "group2" {
  name     = "groupName"
  comments = "this is a group comments."
  force    = true
}

resource "alicloud_ram_policy" "policy2" {
  name        = "policyName"
  document    = <<EOF
    {
      "Statement": [
        {
          "Action": [
            "oss:ListObjects",
            "oss:GetObject"
          ],
          "Effect": "Allow",
          "Resource": [
            "acs:oss:*:*:mybucket",
            "acs:oss:*:*:mybucket/*"
          ]
        }
      ],
        "Version": "1"
    }
  EOF
  description = "this is a policy test"
  force       = true
}

resource "alicloud_ram_group_policy_attachment" "attach" {
  policy_name = alicloud_ram_policy.policy2.name
  policy_type = alicloud_ram_policy.policy2.type
  group_name  = alicloud_ram_group.group2.name
}

```
## Non-Compliant Code Examples
```terraform
# Create a RAM User Policy attachment.
resource "alicloud_ram_user" "user1" {
  name         = "userName"
  display_name = "user_display_name"
  mobile       = "86-18688888888"
  email        = "hello.uuu@aaa.com"
  comments     = "yoyoyo"
  force        = true
}

resource "alicloud_ram_policy" "policy1" {
  name        = "policyName"
  document    = <<EOF
  {
    "Statement": [
      {
        "Action": [
          "oss:ListObjects",
          "oss:GetObject"
        ],
        "Effect": "Allow",
        "Resource": [
          "acs:oss:*:*:mybucket",
          "acs:oss:*:*:mybucket/*"
        ]
      }
    ],
      "Version": "1"
  }
  EOF
  description = "this is a policy test"
  force       = true
}

resource "alicloud_ram_user_policy_attachment" "attach" {
  policy_name = alicloud_ram_policy.policy1.name
  policy_type = alicloud_ram_policy.policy1.type
  user_name   = alicloud_ram_user.user1.name
}

```