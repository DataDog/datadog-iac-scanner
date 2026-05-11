---
title: "Disk encryption disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/disk_encryption_disabled"
  id: "ansible-gcp-disk-encryption-disabled"
  display_name: "Disk encryption disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `ansible-gcp-disk-encryption-disabled`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_disk_module.html)

### Description

VM disks must be encrypted using customer-supplied (CSEK) or customer-managed (CMEK) keys. This ensures you retain control over key lifecycle and reduces the risk of cloud-managed keys being used to decrypt sensitive data without your authorization.

For Ansible resources using `google.cloud.gcp_compute_disk` (or `gcp_compute_disk`), the `disk_encryption_key` property must be defined and contain either a non-empty `kms_key_name` (CMEK) or a non-empty `raw_key` (CSEK). This rule flags disks where `disk_encryption_key` is missing or `null`, where both `raw_key` and `kms_key_name` are absent, or where either subproperty is an empty string.

Prefer using `kms_key_name` (a full KMS crypto key resource name, for example, `projects/.../locations/.../keyRings/.../cryptoKeys/...`) and avoid hardcoding `raw_key` in source code—store secrets in a secure secret manager.

Secure configuration examples:

```yaml
- name: create disk with CMEK
  google.cloud.gcp_compute_disk:
    name: my-disk
    zone: us-central1-a
    size_gb: 100
    disk_encryption_key:
      kms_key_name: projects/my-project/locations/global/keyRings/my-kr/cryptoKeys/my-key
```

```yaml
- name: create disk with CSEK (raw key stored securely, not in plaintext)
  google.cloud.gcp_compute_disk:
    name: my-disk
    zone: us-central1-a
    size_gb: 100
    disk_encryption_key:
      raw_key: REDACTED_BASE64_KEY
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: create a disk
  google.cloud.gcp_compute_disk:
    name: test_object
    size_gb: 50
    disk_encryption_key:
      raw_key: SGVsbG8gZnJvbSBHb29nbGUgQ2xvdWQgUGxhdGZvcm0=
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present

```

```yaml
#this code is a correct code for which the query should not find any result
- name: create a disk
  google.cloud.gcp_compute_disk:
    name: test_object
    size_gb: 50
    disk_encryption_key:
      kms_key_name: disk-crypto-key
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: create a disk3
  google.cloud.gcp_compute_disk:
    name: test_object3
    size_gb: 50
    disk_encryption_key:
      kms_key_name:
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a disk4
  google.cloud.gcp_compute_disk:
    name: test_object4
    size_gb: 50
    disk_encryption_key:
      kms_key_name: ""
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```

```yaml
#this is a problematic code where the query should report a result(s)
- name: create a disk1
  google.cloud.gcp_compute_disk:
    name: test_object1
    size_gb: 50
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a disk3
  google.cloud.gcp_compute_disk:
    name: test_object3
    size_gb: 50
    disk_encryption_key:
      raw_key:
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a disk4
  google.cloud.gcp_compute_disk:
    name: test_object4
    size_gb: 50
    disk_encryption_key:
      raw_key: ""
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```