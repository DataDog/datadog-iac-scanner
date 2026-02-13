---
title: "OSS bucket allows all actions from all principals"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/oss_bucket_allows_all_actions_from_all_principals"
  id: "ec62a32c-a297-41ca-a850-cab40b42094a"
  display_name: "OSS bucket allows all actions from all principals"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `ec62a32c-a297-41ca-a850-cab40b42094a`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#policy)

### Description

 OSS buckets must not allow all actions (`*`) from all principals, as this can expose private data or permit unauthorized modification or deletion. This rule inspects the `policy` attribute of `alicloud_oss_bucket` resources to detect such configurations. Specifically, `Effect` must not be `Allow` when both `Action` and `Principal` are set to `*`.


## Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket-policy1" {
  bucket = "bucket-1-policy"
  acl    = "private"

  policy = <<POLICY
  {"Statement": [
    {
        "Action": [
            "oss:ListObjects"
        ],
        "Effect": "Allow",
        "Principal": [
            "*"
        ],
        "Resource": [
            "acs:oss:*:174649585760xxxx:examplebucket"
        ]
    }
  ],
   "Version":"1"}
  POLICY
}

```

```terraform
resource "alicloud_oss_bucket" "bucket-policy1" {
  bucket = "bucket-1-policy"
  acl    = "private"

  policy = <<POLICY
  {"Statement": [
    {
        "Action": [
            "oss:*"
        ],
        "Effect": "Deny",
        "Principal": [
            "*"
        ],
        "Resource": [
            "acs:oss:*:174649585760xxxx:examplebucket"
        ]
    }
  ],
   "Version":"1"}
  POLICY
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket-policy1" {
  bucket = "bucket-1-policy"
  acl    = "private"

  policy = <<POLICY
  {"Statement": [
    {
        "Action": [
            "oss:*"
        ],
        "Effect": "Allow",
        "Principal": [
            "*"
        ],
        "Resource": [
            "acs:oss:*:174649585760xxxx:examplebucket"
        ]
    }
  ],
   "Version":"1"}
  POLICY
}

```