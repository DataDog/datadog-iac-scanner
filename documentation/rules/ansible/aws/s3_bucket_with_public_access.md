---
title: "S3 Bucket With Public Access"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_with_public_access"
  id: "c3e073c1-f65e-4d18-bd67-4a8f20ad1ab9"
  display_name: "S3 Bucket With Public Access"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `c3e073c1-f65e-4d18-bd67-4a8f20ad1ab9`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/aws_s3_module.html#parameter-permission)

### Description

Ansible tasks that set S3 `permission` to `public` create publicly accessible buckets or objects, risking data exposure and regulatory non‑compliance. For the `amazon.aws.aws_s3` and `aws_s3` modules, the `permission` property must be defined and must not contain the value `public`; use `private` or other restricted values (for example, `authenticated-read`) as appropriate. This rule flags tasks where `permission` contains `public`; tasks missing an explicit `permission` should be reviewed and set to a non‑public value.

Secure example:

```yaml
- name: Create private S3 bucket
  amazon.aws.aws_s3:
    bucket: my-bucket
    permission: private
    mode: create
```

## Compliant Code Examples
```yaml
- name: Create an empty bucket
  amazon.aws.aws_s3:
    bucket: mybucket
    mode: create
    permission: private
- name: Create an empty bucket 02
  amazon.aws.aws_s3:
    bucket: mybucket
    mode: create

```
## Non-Compliant Code Examples
```yaml
---
- name: Create an empty bucket
  amazon.aws.aws_s3:
    bucket: mybucket
    mode: create
    permission: public-read
- name: Create an empty bucket 01
  amazon.aws.aws_s3:
    bucket: mybucket 01
    mode: create
    permission: public-read-write

```