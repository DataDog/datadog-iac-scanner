---
title: "VM With Full Cloud Access"
group_id: "Ansible / GCP"
meta:
  name: "gcp/vm_with_full_cloud_access"
  id: "bc20bbc6-0697-4568-9a73-85af1dd97bdd"
  display_name: "VM With Full Cloud Access"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `bc20bbc6-0697-4568-9a73-85af1dd97bdd`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_instance_module.html#parameter-service_accounts/scopes)

### Description

Granting the "cloud-platform" OAuth scope to a VM's service account gives that instance full access to all Google Cloud APIs, increasing the blast radius if the VM or its credentials are compromised and enabling unintended lateral movement or data access. In Ansible tasks using `google.cloud.gcp_compute_instance` or `gcp_compute_instance`, inspect the `service_accounts` property's `scopes` list and ensure it does not contain the cloud-platform scope (e.g., `cloud-platform` or `https://www.googleapis.com/auth/cloud-platform`). Resources with `service_accounts.scopes` containing the cloud-platform scope will be flagged; instead specify only the minimal OAuth scopes required for the workload or avoid broad instance-level scopes by assigning appropriate IAM roles to the service account or using Workload Identity. Secure configuration example with a limited scope:

```yaml
- name: Create VM with minimal OAuth scopes
  google.cloud.gcp_compute_instance:
    name: my-instance
    machine_type: n1-standard-1
    service_accounts:
      - email: my-service-account@project.iam.gserviceaccount.com
        scopes:
          - https://www.googleapis.com/auth/compute.readonly
```

## Compliant Code Examples
```yaml
- name: create a instance
  google.cloud.gcp_compute_instance:
    name: test_object
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: create a instance
  google.cloud.gcp_compute_instance:
    name: test_object
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_accounts:
      - scopes:
          - cloud-platform
    state: present

```