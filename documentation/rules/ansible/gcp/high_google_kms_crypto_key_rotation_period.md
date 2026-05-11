---
title: "High Google KMS crypto key rotation period"
group_id: "Ansible / GCP"
meta:
  name: "gcp/high_google_kms_crypto_key_rotation_period"
  id: "ansible-gcp-high-google-kms-crypto-key-rotation-period"
  display_name: "High Google KMS crypto key rotation period"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `ansible-gcp-high-google-kms-crypto-key-rotation-period`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_kms_crypto_key_module.html)

### Description

KMS crypto keys must have a `rotation_period` of 90 days or less to limit key lifetime and reduce the blast radius if a key is compromised.

For Ansible resources using `google.cloud.gcp_kms_crypto_key` or `gcp_kms_crypto_key`, the `rotation_period` property must be a duration string in seconds ending with an `s`. The numeric value must be less than or equal to `7776000` (90 days). Resources missing `rotation_period`, lacking the `s` suffix, or with a value greater than `7776000` are flagged.

Secure configuration example:

```yaml
- name: Create KMS crypto key with 90-day rotation
  google.cloud.gcp_kms_crypto_key:
    name: my-key
    key_ring: projects/my-project/locations/global/keyRings/my-keyring
    purpose: ENCRYPT_DECRYPT
    rotation_period: "7776000s"
    state: present
```

## Compliant Code Examples
```yaml
- name: create a key ring
  google.cloud.gcp_kms_key_ring:
    name: key-key-ring
    location: us-central1
    project: '{{ gcp_project }}'
    auth_kind: '{{ gcp_cred_kind }}'
    service_account_file: '{{ gcp_cred_file }}'
    state: present
  register: keyring

- name: create a crypto key
  google.cloud.gcp_kms_crypto_key:
    name: test_object
    key_ring: projects/{{ gcp_project }}/locations/us-central1/keyRings/key-key-ring
    project: test_project
    auth_kind: serviceaccount
    rotation_period: 7776000s
    service_account_file: /tmp/auth.pem
    state: present

```
## Non-Compliant Code Examples
```yaml
---
- name: create a key ring
  google.cloud.gcp_kms_key_ring:
    name: key-key-ring
    location: us-central1
    project: "{{ gcp_project }}"
    auth_kind: "{{ gcp_cred_kind }}"
    service_account_file: "{{ gcp_cred_file }}"
    state: present
  register: keyring

- name: create a crypto key
  google.cloud.gcp_kms_crypto_key:
    name: test_object
    key_ring: projects/{{ gcp_project }}/locations/us-central1/keyRings/key-key-ring
    project: test_project
    auth_kind: serviceaccount
    rotation_period: "315356000s"
    service_account_file: "/tmp/auth.pem"
    state: present

- name: create a crypto key2
  google.cloud.gcp_kms_crypto_key:
    name: test_object
    key_ring: projects/{{ gcp_project }}/locations/us-central1/keyRings/key-key-ring
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```