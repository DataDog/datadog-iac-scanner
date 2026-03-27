---
title: "Project-wide SSH keys are enabled in VM instances"
group_id: "Ansible / GCP"
meta:
  name: "gcp/project_wide_ssh_keys_are_enabled_in_vm_instances"
  id: "099b4411-d11e-4537-a0fc-146b19762a79"
  display_name: "Project-wide SSH keys are enabled in VM instances"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `099b4411-d11e-4537-a0fc-146b19762a79`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_instance_module.html)

### Description

VM instances should block project-wide SSH keys. This prevents SSH keys defined at the project level from granting access to individual instances, reducing the risk of unintended or persistent SSH access and lateral movement if project metadata or keys are compromised.

For Ansible resources using `google.cloud.gcp_compute_instance` or `gcp_compute_instance`, ensure the `metadata.block-project-ssh-keys` property is defined and set to `true`. Resources that omit the `metadata` map, omit the `block-project-ssh-keys` key, or set it to `false` are flagged. 

Secure configuration example for an Ansible task:

```yaml
- name: Create VM with project-wide SSH keys blocked
  google.cloud.gcp_compute_instance:
    name: my-instance
    machine_type: e2-medium
    metadata:
      block-project-ssh-keys: true
```

## Compliant Code Examples
```yaml
- name: ssh_keys_blocked
  google.cloud.gcp_compute_instance:
    metadata:
      block-project-ssh-keys: yes
    zone: us-central1-a
    auth_kind: serviceaccount

```
## Non-Compliant Code Examples
```yaml
- name: ssh_keys_unblocked
  google.cloud.gcp_compute_instance:
    metadata:
      block-project-ssh-keys: no
    zone: us-central1-a
    auth_kind: serviceaccount
- name: ssh_keys_missing
  google.cloud.gcp_compute_instance:
    metadata:
      startup-script-url: gs:://graphite-playground/bootstrap.sh
      cost-center: '12345'
    zone: us-central1-a
    auth_kind: serviceaccount
- name: no_metadata
  google.cloud.gcp_compute_instance:
    zone: us-central1-a
    auth_kind: serviceaccount

```