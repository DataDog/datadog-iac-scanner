---
title: "S3 bucket without server-side encryption"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_without_server-side_encryption"
  id: "ansible-aws-s3-bucket-without-server-side-encryption"
  display_name: "S3 bucket without server-side encryption"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-s3-bucket-without-server-side-encryption{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/s3_bucket_module.html)

### Description

S3 buckets should have server-side encryption (SSE) enabled to protect data at rest and prevent exposure of sensitive objects if a bucket is misconfigured or storage media is accessed.

For Ansible tasks using the amazon.aws.s3_bucket or s3_bucket modules, the `encryption` property must not be set to `'none'` and should be configured to a valid SSE algorithm such as `'AES256'` or `'aws:kms'`. Resources that omit the `encryption` property or explicitly set `encryption: 'none'` are flagged.

When using `'aws:kms'`, also specify and manage a KMS key (for example via `kms_key_id`) to retain control over encryption keys and meet organizational access requirements.

Secure example using KMS-managed keys:

```yaml
- name: Create S3 bucket with KMS encryption
  amazon.aws.s3_bucket:
    name: my-secure-bucket
    encryption: aws:kms
    kms_key_id: arn:aws:kms:us-east-1:123456789012:key/abcd-ef01-2345-6789
```

## Compliant Code Examples
```yaml
- name: Create a simple s3 bucket v2
  amazon.aws.s3_bucket:
    name: mys3bucket
    state: present
    encryption: aws:kms

```
## Non-Compliant Code Examples
```yaml
- name: Create a simple s3 bucket
  amazon.aws.s3_bucket:
    name: mys3bucket
    state: present
    encryption: "none"

```