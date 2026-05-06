---
title: "S3 bucket logging disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_logging_disabled"
  id: "c3b9f7b0-f5a0-49ec-9cbc-f1e346b7274d"
  display_name: "S3 bucket logging disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}c3b9f7b0-f5a0-49ec-9cbc-f1e346b7274d{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/s3_bucket_module.html#parameter-debug_botocore_endpoint_logs)

### Description

Enabling botocore endpoint debug logs for S3 operations captures detailed client request and response traces useful for detecting suspicious activity and supporting incident investigation. For Ansible tasks using the `amazon.aws.s3_bucket` or `s3_bucket` modules, the `debug_botocore_endpoint_logs` property must be defined and set to `true`. Tasks where this property is missing or set to `false` are flagged.

Debug logs can contain sensitive request data. Ensure they are collected, transmitted, and stored securely with appropriate access controls and retention policies.

Secure configuration example:

```yaml
- name: Create S3 bucket with botocore endpoint debug logs enabled
  amazon.aws.s3_bucket:
    name: my-bucket
    state: present
    debug_botocore_endpoint_logs: true
```

## Compliant Code Examples
```yaml
- amazon.aws.s3_bucket:
    name: mys3bucket
    state: present
    debug_botocore_endpoint_logs: true

```
## Non-Compliant Code Examples
```yaml
---
- name: "Create S3 bucket"
  amazon.aws.s3_bucket:
    name: mys3bucket
    state: present
    debug_botocore_endpoint_logs: false

```