---
title: "Cloud Storage Bucket Versioning Disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/cloud_storage_bucket_versioning_disabled"
  id: "7814ddda-e758-4a56-8be3-289a81ded929"
  display_name: "Cloud Storage Bucket Versioning Disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `7814ddda-e758-4a56-8be3-289a81ded929`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_storage_bucket_module.html#parameter-versioning)

### Description

Cloud Storage buckets should have object versioning enabled to protect against accidental or malicious object deletion and to allow recovery of prior object states. In Ansible, tasks using the `google.cloud.gcp_storage_bucket` or `gcp_storage_bucket` modules must define the `versioning` parameter and set `versioning.enabled` to `true`. Resources missing the `versioning` parameter or with `versioning.enabled` set to `false` will be flagged. Secure configuration example:

```yaml
- name: Create GCS bucket with versioning
  google.cloud.gcp_storage_bucket:
    name: my-bucket
    versioning:
      enabled: true
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
    versioning:
      enabled: yes

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
- name: create a second bucket
  google.cloud.gcp_storage_bucket:
    name: ansible-storage-module
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
    versioning:
      enabled: no

```