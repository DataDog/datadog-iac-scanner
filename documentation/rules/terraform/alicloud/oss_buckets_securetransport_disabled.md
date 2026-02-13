---
title: "OSS buckets secure transport disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/oss_buckets_securetransport_disabled"
  id: "c01d10de-c468-4790-b3a0-fc887a56f289"
  display_name: "OSS buckets secure transport disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `c01d10de-c468-4790-b3a0-fc887a56f289`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#policy)

### Description

 OSS buckets should have secure transport enabled. The bucket policy should deny requests when `acs:SecureTransport` is `false`, or allow requests only when `acs:SecureTransport` is `true`. This condition must apply to any principal. Enforcing this prevents acceptance of HTTP requests and ensures data is transferred over TLS.


## Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket-securetransport4"{
        policy = <<POLICY
{
        "Version": "1",
        "Statement": 
        [
            {
                "Effect": "Allow",
                "Action": 
                [
                    "oss:RestoreObject",
                    "oss:ListObjects",
                    "oss:AbortMultipartUpload",
                    "oss:PutObjectAcl",
                    "oss:GetObjectAcl",
                    "oss:ListParts",
                    "oss:DeleteObject",
                    "oss:PutObject",
                    "oss:GetObject",
                    "oss:GetVodPlaylist",
                    "oss:PostVodPlaylist",
                    "oss:PublishRtmpStream",
                    "oss:ListObjectVersions",
                    "oss:GetObjectVersion",
                    "oss:GetObjectVersionAcl",
                    "oss:RestoreObjectVersion"
                ],
                "Principal": 
                [
                    "*"
                ],
                "Resource": 
                [
                    "acs:oss:*:0000111122223334:af/*"
                ],
                "Condition": 
                {
                    "Bool": 
                    {
                        "acs:SecureTransport": [ "true" ]
                    }
                }
            }
        ]
}
POLICY

}
    

```

```terraform
resource "alicloud_oss_bucket" "bucket-securetransport2"{
        policy = <<POLICY
{
        "Version": "1",
        "Statement": 
        [
            {
                "Effect": "Deny",
                "Action": 
                [
                    "oss:RestoreObject",
                    "oss:ListObjects",
                    "oss:AbortMultipartUpload",
                    "oss:PutObjectAcl",
                    "oss:GetObjectAcl",
                    "oss:ListParts",
                    "oss:DeleteObject",
                    "oss:PutObject",
                    "oss:GetObject",
                    "oss:GetVodPlaylist",
                    "oss:PostVodPlaylist",
                    "oss:PublishRtmpStream",
                    "oss:ListObjectVersions",
                    "oss:GetObjectVersion",
                    "oss:GetObjectVersionAcl",
                    "oss:RestoreObjectVersion"
                ],
                "Principal": 
                [
                    "*"
                ],
                "Resource": 
                [
                    "acs:oss:*:0000111122223334:af/*"
                ],
                "Condition": 
                {
                    "Bool": 
                    {
                        "acs:SecureTransport": [ "false" ]
                    }
                }
            }
        ]
}
POLICY

}
    

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_oss_bucket" "bucket-securetransport3" {
  bucket = "bucket-170309-policy"
  acl    = "private"

  policy = <<POLICY
  {"Statement":
      [{"Action":
          ["oss:PutObject", "oss:GetObject", "oss:DeleteBucket"],
        "Effect":"Allow",
        "Resource":
            ["acs:oss:*:*:*"]}],
   "Version":"1"}
  POLICY
}

```

```terraform
resource "alicloud_oss_bucket" "bucket-securetransport1"{
        policy = <<POLICY
{
        "Version": "1",
        "Statement": 
        [
            {
                "Effect": "Allow",
                "Action": 
                [
                    "oss:RestoreObject",
                    "oss:ListObjects",
                    "oss:AbortMultipartUpload",
                    "oss:PutObjectAcl",
                    "oss:GetObjectAcl",
                    "oss:ListParts",
                    "oss:DeleteObject",
                    "oss:PutObject",
                    "oss:GetObject",
                    "oss:GetVodPlaylist",
                    "oss:PostVodPlaylist",
                    "oss:PublishRtmpStream",
                    "oss:ListObjectVersions",
                    "oss:GetObjectVersion",
                    "oss:GetObjectVersionAcl",
                    "oss:RestoreObjectVersion"
                ],
                "Principal": 
                [
                    "*"
                ],
                "Resource": 
                [
                    "acs:oss:*:0000111122223334:af/*"
                ],
                "Condition": 
                {
                    "Bool": 
                    {
                        "acs:SecureTransport": [ "false" ]
                    }
                }
            }
        ]
}
POLICY

}
    


```