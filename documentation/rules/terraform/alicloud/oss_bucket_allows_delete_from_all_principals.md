---
title: "OSS bucket allows delete action from all principals"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/oss_bucket_allows_delete_from_all_principals"
  id: "8c0695d8-2378-4cd6-8243-7fd5894fa574"
  display_name: "OSS bucket allows delete action from all principals"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `8c0695d8-2378-4cd6-8243-7fd5894fa574`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#policy)

### Description

An `alicloud_oss_bucket` should not allow the `DeleteBucket` action from all principals. Allowing this action may expose private data or enable unauthorized deletion or tampering. This rule asserts that `Effect` must not be `Allow` when `Action` is `DeleteBucket` and `Principal` is set to `"*"`. The policy evaluated is the `policy` attribute on the `alicloud_oss_bucket` resource.

## Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket-policy4" {
  bucket = "bucket-4-policy"
  acl    = "private"

  policy = <<POLICY
  {"Statement": [
    {
        "Action": [
            "oss:PutObject", "oss:DeleteBucket"
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

```terraform
resource "alicloud_oss_bucket" "bucket-policy3" {
  bucket = "bucket-3-policy"
  acl    = "private"

  policy = <<POLICY
  {"Statement": [
    {
        "Action": [
            "oss:PutObject", "oss:DeleteBucket"
        ],
        "Effect": "Allow",
        "Principal": [
            "20214760404935xxxx"
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
resource "alicloud_oss_bucket" "bucket-policy2" {
  bucket = "bucket-2-policy"
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
## Non-Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket-policy1" {
  bucket = "bucket-1-policy"
  acl    = "private"

  policy = <<POLICY
  {"Statement": [
    {
        "Action": [
            "oss:PutObject", "oss:DeleteBucket"
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