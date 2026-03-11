---
title: "Google Compute SSL Policy Weak Cipher In Use"
group_id: "Ansible / GCP"
meta:
  name: "gcp/google_compute_ssl_policy_weak_cipher_in_use"
  id: "b28bcd2f-c309-490e-ab7c-35fc4023eb26"
  display_name: "Google Compute SSL Policy Weak Cipher In Use"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `b28bcd2f-c309-490e-ab7c-35fc4023eb26`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_ssl_policy_module.html)

### Description

Compute SSL policies must enforce a minimum TLS version of TLS_1_2 to prevent use of older, vulnerable protocol versions and to avoid permitting weak cipher suites. The `min_tls_version` property on `google.cloud.gcp_compute_ssl_policy` (or `gcp_compute_ssl_policy`) resources must be defined and set to `TLS_1_2`. Resources that omit `min_tls_version` or set it to any other value will be flagged.

```yaml
- name: Create SSL policy with TLS 1.2 minimum
  google.cloud.gcp_compute_ssl_policy:
    name: my-ssl-policy
    profile: MODERN
    min_tls_version: TLS_1_2
```

## Compliant Code Examples
```yaml
- name: create a SSL policy
  google.cloud.gcp_compute_ssl_policy:
    name: test_object
    profile: CUSTOM
    min_tls_version: TLS_1_2
    custom_features:
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: create a SSL policy
  google.cloud.gcp_compute_ssl_policy:
    name: test_object
    profile: CUSTOM
    custom_features:
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a SSL policy2
  google.cloud.gcp_compute_ssl_policy:
    name: test_object2
    profile: CUSTOM
    min_tls_version: TLS_1_1
    custom_features:
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```