---
title: "Cloud storage bucket logging not enabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/cloud_storage_bucket_logging_not_enabled"
  id: "507df964-ad97-4035-ab14-94a82eabdfdd"
  display_name: "Cloud storage bucket logging not enabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** {{</* copyable-code */>}}507df964-ad97-4035-ab14-94a82eabdfdd{{</* copyable-code */>}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_storage_bucket_module.html#parameter-logging)

### Description

Cloud Storage buckets must have access logging enabled to provide audit trails for object access and modifications. This is critical for detecting and investigating unauthorized access, data exfiltration, and operational incidents.

For Ansible tasks using the `google.cloud.gcp_storage_bucket` or `gcp_storage_bucket` modules, the `logging` property must be defined. It should specify a `logBucket` (the destination bucket for logs) and may include `logObjectPrefix` to organize log objects.

Resources missing the `logging` property are flagged. Ensure the designated log bucket exists and has the necessary IAM permissions so logs can be written and retained according to your retention and compliance requirements.

Secure example (Ansible task):

```yaml
- name: Create GCS bucket with access logging enabled
  google.cloud.gcp_storage_bucket:
    name: my-data-bucket
    logging:
      logBucket: my-logs-bucket
      logObjectPrefix: access-logs/
```

## Compliant Code Examples
```yaml
- name: create a bucket
  google.cloud.gcp_storage_bucket:
    name: ansible-storage-module
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present
    logging:
      log_bucket: a_bucket_for_logs
      log_object_prefix: log

```
## Non-Compliant Code Examples
```yaml
---
- name: create a bucket
  google.cloud.gcp_storage_bucket:
    name: ansible-storage-module
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```