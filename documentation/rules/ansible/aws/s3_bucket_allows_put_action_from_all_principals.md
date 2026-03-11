---
title: "S3 Bucket Allows Put Action From All Principals"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_allows_put_action_from_all_principals"
  id: "a0f1bfe0-741e-473f-b3b2-13e66f856fab"
  display_name: "S3 Bucket Allows Put Action From All Principals"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `a0f1bfe0-741e-473f-b3b2-13e66f856fab`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/s3_bucket_module.html)

### Description

S3 bucket policy statements that Allow Put actions to all principals (Principal='*' and Effect='Allow') let anyone upload or overwrite objects, risking data tampering, malware injection, and unauthorized exposure of sensitive data. This rule inspects Ansible `amazon.aws.s3_bucket` and `s3_bucket` resources' `policy` statements and flags any statement where `Effect` is `"Allow"`, `Principal` is `"*"`, and `Action` includes Put operations (for example `s3:PutObject` or any action name containing "Put"). Remediate by restricting Put permissions to explicit principals (AWS account ARNs, IAM role ARNs, or service principals), applying least-privilege permissions and conditions, or removing public Put permissions entirely.

Secure example with a restricted principal:

```yaml
- name: Create S3 bucket with restricted Put permissions
  amazon.aws.s3_bucket:
    name: my-bucket
    policy: |
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Sid": "AllowPutForSpecificAccount",
            "Effect": "Allow",
            "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
            "Action": [ "s3:PutObject" ],
            "Resource": "arn:aws:s3:::my-bucket/*"
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
      - Effect: Allow
        Action: PutObject
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
        Action: PutObject
        Principal: "*"

```