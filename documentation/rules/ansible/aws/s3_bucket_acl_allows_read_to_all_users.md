---
title: "S3 bucket ACL allows read access to all users"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_acl_allows_read_to_all_users"
  id: "ansible-aws-s3-bucket-acl-allows-read-access-to-all-users"
  display_name: "S3 bucket ACL allows read access to all users"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `ansible-aws-s3-bucket-acl-allows-read-access-to-all-users`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/s3_object_module.html#parameter-permission)

### Description

S3 buckets must not be configured to allow read access to all users. Public-read ACLs make objects and metadata accessible to anyone on the internet, risking data exposure and compliance violations.

For Ansible tasks using the `amazon.aws.s3_object` or `s3_object` modules, the `permission` parameter must not be set to values that start with `public-read` (for example `public-read` or `public-read-write`). Tasks with `permission` omitted or set to restrictive values such as `private`, or that rely on explicit bucket policies to grant scoped access, are acceptable. Resources with `permission` starting with `public-read` are flagged. Secure configuration example:

```yaml
- name: Create S3 bucket with private ACL
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
- name: Create an empty bucket2
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
- name: Create an empty bucket2
  amazon.aws.s3_object:
    bucket: mybucket
    object: my-object-2
    mode: create
    permission: public-read-write

```