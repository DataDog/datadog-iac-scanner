---
title: "S3 bucket ACL allows read access to any authenticated user"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_acl_allows_read_to_any_authenticated_user"
  id: "75480b31-f349-4b9a-861f-bce19588e674"
  display_name: "S3 bucket ACL allows read access to any authenticated user"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `75480b31-f349-4b9a-861f-bce19588e674`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/s3_object_module.html#parameter-permission)

### Description

S3 objects or buckets configured with the `authenticated-read` ACL allow any AWS authenticated user to read your data. This exposes content beyond your account boundary and increases the risk of unauthorized data access or leakage.

In Ansible, tasks using the `amazon.aws.s3_object` or `s3_object` modules must not set the `permission` parameter to `authenticated-read`. Prefer `permission: private` or enforce access via explicit bucket policies or IAM roles. This rule flags Ansible tasks where `permission` is exactly `authenticated-read`.

Secure example:

```yaml
- name: Upload file to S3 with private ACL
  amazon.aws.s3_object:
    bucket: my-bucket
    object: path/file.txt
    src: /local/file.txt
    permission: private
```

## Compliant Code Examples
```yaml
- name: Create an empty bucket
  amazon.aws.s3_object:
    bucket: mybucket
    mode: create
- name: Create an empty bucket2
  amazon.aws.s3_object:
    bucket: mybucket
    mode: create
    permission: private

```
## Non-Compliant Code Examples
```yaml
---
- name: Create an empty bucket2
  amazon.aws.s3_object:
    bucket: mybucket
    mode: create
    permission: authenticated-read

```