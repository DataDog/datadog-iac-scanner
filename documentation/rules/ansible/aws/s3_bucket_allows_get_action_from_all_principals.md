---
title: "S3 bucket allows GET action from all principals"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_allows_get_action_from_all_principals"
  id: "53bce6a8-5492-4b1b-81cf-664385f0c4bf"
  display_name: "S3 bucket allows GET action from all principals"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** {{</* copyable-code */>}}53bce6a8-5492-4b1b-81cf-664385f0c4bf{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/s3_bucket_module.html)

### Description

S3 bucket policies must not grant Get actions to all principals ("*"). Allowing public read access exposes bucket objects to unauthorized disclosure and accidental data leaks. For Ansible S3 bucket resources (modules `amazon.aws.s3_bucket` and `s3_bucket`), inspect the `policy` property for any Statement with `Effect: "Allow"`, `Principal: "*"`, and an `Action` that includes Get operations (for example, `s3:GetObject` or any action name containing "Get"). Such statements are flagged.

Restrict access by specifying explicit principals (AWS account IDs, roles, or ARNs), narrowing the allowed actions, or adding conditions (IP/VPC, MFA, or other constraints). If public access is required, use presigned URLs or a controlled distribution layer rather than a public bucket policy.

Secure example with an explicit principal:

```yaml
- name: Create S3 bucket with restricted policy
  amazon.aws.s3_bucket:
    name: my-bucket
    policy:
      Version: "2012-10-17"
      Statement:
        - Sid: "AllowSpecificAccountGet"
          Effect: "Allow"
          Principal:
            AWS: "arn:aws:iam::123456789012:role/ReadOnlyRole"
          Action:
            - "s3:GetObject"
          Resource: "arn:aws:s3:::my-bucket/*"
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
      - Effect: Allow
        Action: GetObject
        Principal: NotAll

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
        Action: GetObject
        Principal: "*"

```