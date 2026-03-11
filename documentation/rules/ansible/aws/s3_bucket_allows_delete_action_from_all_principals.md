---
title: "S3 Bucket Allows Delete Action From All Principals"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_allows_delete_action_from_all_principals"
  id: "6fa44721-ef21-41c6-8665-330d59461163"
  display_name: "S3 Bucket Allows Delete Action From All Principals"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `6fa44721-ef21-41c6-8665-330d59461163`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/s3_bucket_module.html)

### Description

S3 bucket policies must not grant delete permissions to all principals ('*'), because public delete rights can enable unauthorized data tampering or complete data loss by allowing anyone on the internet to remove objects or buckets. For Ansible S3 resources (`amazon.aws.s3_bucket` or `s3_bucket`), ensure the `policy` document contains no Statement with `Effect: "Allow"`, `Principal: "*"`, and an `Action` that includes delete operations (for example `s3:DeleteObject` or `s3:DeleteBucket`). This rule flags bucket resources whose `policy` includes an Allow statement granting delete-related actions to the wildcard principal; instead, restrict delete permissions to specific AWS account IDs, IAM roles/ARNs, or remove delete actions for public principals.  

Secure example restricting delete to a specific AWS account:

```yaml
- name: Create S3 bucket with restricted delete permissions
  amazon.aws.s3_bucket:
    name: my-bucket
    policy: |
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Sid": "AllowSpecificAccountDelete",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": ["s3:DeleteObject", "s3:DeleteBucket"],
            "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
          }
        ]
      }
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: Bucket
  amazon.aws.s3_bucket:
    name: mys3bucket
    state: present
    policy:
      Version: '2020-10-07'
      Statement:
      - Effect: Deny
        Action: DeleteObject
        Principal: '*'

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: Bucket
  amazon.aws.s3_bucket:
    name: mys3bucket
    state: present
    policy:
      Version: "2020-10-07"
      Statement:
      - Effect: Allow
        Action: DeleteObject
        Principal: "*"

```