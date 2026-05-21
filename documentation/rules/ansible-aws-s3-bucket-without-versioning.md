---
title: "S3 bucket without versioning"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_without_versioning"
  id: "ansible-aws-s3-bucket-without-versioning"
  display_name: "S3 bucket without versioning"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-s3-bucket-without-versioning{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/s3_bucket_module.html#parameter-versioning)

### Description

S3 buckets must have versioning enabled to protect objects from accidental or malicious deletion and retain prior versions for recovery, forensics, and compliance. For Ansible tasks using the `amazon.aws.s3_bucket` or `s3_bucket` modules, the `versioning` property must be defined and set to `true`. When omitted, the module defaults to versioning disabled. This rule flags tasks where the `versioning` key is missing or explicitly set to `false`.

Secure configuration example:

```yaml
- name: Ensure S3 bucket with versioning enabled
  amazon.aws.s3_bucket:
    name: my-bucket
    versioning: true
```

## Compliant Code Examples
```yaml
- name: foo
  amazon.aws.s3_bucket:
    name: mys3bucket
    policy: "{{ lookup('file','policy.json') }}"
    requester_pays: yes
    versioning: yes
    tags:
      example: tag1
      another: tag2

```
## Non-Compliant Code Examples
```yaml
---
- name: foo
  amazon.aws.s3_bucket:
    name: mys3bucket
    policy: "{{ lookup('file','policy.json') }}"
    requester_pays: yes
    tags:
      example: tag1
      another: tag2
- name: foo2
  amazon.aws.s3_bucket:
    name: mys3bucket
    policy: "{{ lookup('file','policy.json') }}"
    requester_pays: yes
    versioning: no
    tags:
      example: tag1
      another: tag2

```