---
title: "S3 bucket with all permissions"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_with_all_permissions"
  id: "6a6d7e56-c913-4549-b5c5-5221e624d2ec"
  display_name: "S3 bucket with all permissions"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}6a6d7e56-c913-4549-b5c5-5221e624d2ec{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/s3_bucket_module.html#parameter-policy)

### Description

S3 bucket policies must not grant all actions to all principals. A statement that sets `Effect`=`Allow` with both `Action`=`*` and `Principal`=`*` effectively makes the bucket publicly accessible and can enable data exfiltration or unauthorized modification/deletion.

For Ansible resources using the `amazon.aws.s3_bucket` or `s3_bucket` modules, inspect the resource `policy` document's `Statement` entries. Any statement where `Effect` is `Allow` and both `Action` and `Principal` contain the wildcard `*` (including arrays that include `*`) is flagged.

Restrict `Principal` to explicit ARNs, account IDs, or service principals and scope `Action` to the minimum required permissions following least privilege.

Secure example policy statement:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
      "Action": [ "s3:GetObject" ],
      "Resource": "arn:aws:s3:::example-bucket/*"
    }
  ]
}
```

## Compliant Code Examples
```yaml
- name: Create s3 bucket
  amazon.aws.s3_bucket:
    name: mys3bucket
    policy:
      Id: id113
      Version: '2012-10-17'
      Statement:
      - Action: s3:put
        Effect: Allow
        Resource: arn:aws:s3:::S3B_181355/*
        Principal: '*'
    requester_pays: yes
    versioning: yes

```
## Non-Compliant Code Examples
```yaml
---
- name: Create s3 bucket
  amazon.aws.s3_bucket:
    name: mys3bucket
    policy:
      Id: "id113"
      Version: "2012-10-17"
      Statement:
      - Action: "s3:*"
        Effect: "Allow"
        Resource: "arn:aws:s3:::S3B_181355/*"
        Principal: "*"
    requester_pays: yes
    versioning: yes

```