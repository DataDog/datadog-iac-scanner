---
title: "BigQuery dataset is public"
group_id: "Ansible / GCP"
meta:
  name: "gcp/bigquery_dataset_is_public"
  id: "ansible-gcp-bigquery-dataset-is-public"
  display_name: "BigQuery dataset is public"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `ansible-gcp-bigquery-dataset-is-public`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_bigquery_dataset_module.html#parameter-access/special_group)

### Description

BigQuery datasets must not grant access to the special group `allAuthenticatedUsers`. This allows any Google account to access the dataset, increasing the risk of sensitive data exposure and regulatory non-compliance.

For Ansible tasks using the `google.cloud.gcp_bigquery_dataset` (or `gcp_bigquery_dataset`) module, validate the `access` entries and ensure no entry has `special_group` set to `"allAuthenticatedUsers"` (checked case-insensitively). Resources with `access` entries where `special_group` equals `allAuthenticatedUsers` are flagged. Restrict dataset access to specific users, groups, domains, or predefined roles instead.

Secure Ansible task example (do not include `special_group: allAuthenticatedUsers`):

```yaml
- name: Create BigQuery dataset with restricted access
  google.cloud.gcp_bigquery_dataset:
    dataset_id: my_dataset
    access:
      - role: READER
        userByEmail: alice@example.com
      - role: OWNER
        groupByEmail: admins@example.com
```

## Compliant Code Examples
```yaml
- name: create a dataset
  google.cloud.gcp_bigquery_dataset:
    dataset_id: my_dataset
    name: my_example_dataset
    dataset_reference:
      dataset_id: my_example_dataset
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present

```
## Non-Compliant Code Examples
```yaml
---
- name: create a dataset
  google.cloud.gcp_bigquery_dataset:
    dataset_id: my_dataset
    name: my_example_dataset
    access:
      - special_group: allAuthenticatedUsers
    dataset_reference:
      dataset_id: my_example_dataset
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```