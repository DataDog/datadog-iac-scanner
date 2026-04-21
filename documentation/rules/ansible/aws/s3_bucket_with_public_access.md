---
title: "S3 bucket with public access"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_with_public_access"
  id: "c3e073c1-f65e-4d18-bd67-4a8f20ad1ab9"
  display_name: "S3 bucket with public access"
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

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/s3_object_module.html#parameter-permission)

### Description

Ansible tasks that set S3 `permission` to `public` create publicly accessible buckets or objects, risking data exposure and regulatory non‑compliance. For the `amazon.aws.s3_object` and `s3_object` modules, the `permission` property must be defined and must not contain the value `public`. Use `private` or other restricted values (for example, `authenticated-read`) as appropriate.

This rule flags tasks where `permission` contains `public`. Tasks missing an explicit `permission` should be reviewed and set to a non‑public value.

Secure example:

```yaml
- name: Create private S3 bucket
  amazon.aws.s3_object:
    bucket: my-bucket
    permission: private
    mode: create
```

## Compliant Code Examples
```yaml
- name: Create an empty bucket
  amazon.aws.s3_object:
    bucket: mybucket
    object: my-object
    mode: create
    permission: private
- name: Create an empty bucket 02
  amazon.aws.s3_object:
    bucket: mybucket
    object: my-object-2
    mode: create

```
## Non-Compliant Code Examples
```yaml
---
- name: Create an empty bucket
  amazon.aws.s3_object:
    bucket: mybucket
    object: my-object
    mode: create
    permission: public-read
- name: Create an empty bucket 01
  amazon.aws.s3_object:
    bucket: mybucket 01
    object: my-object-2
    mode: create
    permission: public-read-write

```