---
title: "OSS bucket allows list action from all principals"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/oss_bucket_allows_list_action_from_all_principals"
  id: "88541597-6f88-42c8-bac6-7e0b855e8ff6"
  display_name: "OSS bucket allows list action from all principals"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `88541597-6f88-42c8-bac6-7e0b855e8ff6`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#policy)

### Description

 The `policy` of an `alicloud_oss_bucket` must not allow `List` actions for all principals. Such policies can expose private data or enable unauthorized tampering or deletion. Specifically, `Effect` must not be `Allow` when `Action` includes `List` and `Principal` is set to `"*"`. This rule flags `alicloud_oss_bucket[*].policy` documents that permit `List` actions to all principals.


## Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket-policy4" {
  bucket = "bucket-4-policy"
  acl    = "private"

  policy = <<POLICY
  {"Statement": [
    {
        "Action": [
            "oss:ListObjectVersions", "oss:ListObjects", "oss:ListParts"
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
            "oss:ListObjectVersions", "oss:ListObjects", "oss:ListParts"
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
            "oss:AbortMultipartUpload"
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
resource "alicloud_oss_bucket" "bucket-policy5" {
  bucket = "bucket-5-policy"
  acl    = "private"

  policy = <<POLICY
  {"Statement": [
    {
        "Action": [
            "oss:ListObjectVersions", "oss:RestoreObject"
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
            "oss:ListObjectVersions", "oss:ListObjects", "oss:ListParts"
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