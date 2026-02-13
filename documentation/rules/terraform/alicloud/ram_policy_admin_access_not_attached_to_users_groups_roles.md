---
title: "RAM policy admin access not attached to users groups roles"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/ram_policy_admin_access_not_attached_to_users_groups_roles"
  id: "e8e62026-da63-4904-b402-65adfe3ca975"
  display_name: "RAM policy admin access not attached to users groups roles"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `e8e62026-da63-4904-b402-65adfe3ca975`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/ram_policy)

### Description

 RAM policies that grant administrative access should not be associated with users, groups, or roles. This rule detects policy documents with `Effect = "Allow"` where both `Action` and `Resource` are set to `"*"`. It flags any such policy attached via `alicloud_ram_user_policy_attachment`, `alicloud_ram_group_policy_attachment`, or `alicloud_ram_role_policy_attachment`.


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
## Non-Compliant Code Examples
```terraform
# Create a RAM Group Policy attachment.
resource "alicloud_ram_group" "group5" {
  name     = "groupName"
  comments = "this is a group comments."
  force    = true
}

resource "alicloud_ram_policy" "policy5" {
  name        = "policyName"
  document    = <<EOF
    {
      "Statement": [
        {
          "Action": [
            "oss:*"
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
  policy_name = alicloud_ram_policy.policy5.name
  policy_type = alicloud_ram_policy.policy5.type
  group_name  = alicloud_ram_group.group5.name
}

```

```terraform
# Create a RAM Role Policy attachment.
resource "alicloud_ram_role" "role6" {
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

resource "alicloud_ram_policy" "policy6" {
  name        = "policyName"
  document    = <<EOF
  {
    "Statement": [
      {
        "Action": [
          "oss:*"
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
  policy_name = alicloud_ram_policy.policy6.name
  policy_type = alicloud_ram_policy.policy6.type
  role_name   = alicloud_ram_role.role6.name
}

```

```terraform
# Create a RAM User Policy attachment.
resource "alicloud_ram_user" "user4" {
  name         = "userName"
  display_name = "user_display_name"
  mobile       = "86-18688888888"
  email        = "hello.uuu@aaa.com"
  comments     = "yoyoyo"
  force        = true
}

resource "alicloud_ram_policy" "policy4" {
  name        = "policyName"
  document    = <<EOF
  {
    "Statement": [
      {
        "Action": [
          "oss:*"
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
  policy_name = alicloud_ram_policy.policy4.name
  policy_type = alicloud_ram_policy.policy4.type
  user_name   = alicloud_ram_user.user4.name
}

```