---
title: "OSS bucket IP restriction disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/oss_bucket_ip_restriction_disabled"
  id: "6107c530-7178-464a-88bc-df9cdd364ac8"
  display_name: "OSS bucket IP restriction disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `6107c530-7178-464a-88bc-df9cdd364ac8`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/oss_bucket#policy)

### Description

 OSS bucket policies should restrict access by IP address.
This rule checks the `policy` attribute of `alicloud_oss_bucket` resources for statements that include a `Condition` with `acs:SourceIp`.
Resources without an IP restriction in their `policy` are reported.


## Compliant Code Examples
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
                    "NotIpAdress": 
                    {
                        "acs:SourceIp": "10.0.0.0"
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
                    "IpAdress": 
                    {
                        "acs:SourceIp": "10.0.0.0"
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
resource "alicloud_oss_bucket" "bucket-policy" {
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