---
title: "OSLogin Is Disabled In VM Instance"
group_id: "Ansible / GCP"
meta:
  name: "gcp/oslogin_is_disabled_for_vm_instance"
  id: "66dae697-507b-4aef-be18-eec5bd707f33"
  display_name: "OSLogin Is Disabled In VM Instance"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `66dae697-507b-4aef-be18-eec5bd707f33`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_instance_module.html)

### Description

OS Login should be enabled on Google Compute VM instances to centralize SSH access control via IAM and to avoid unmanaged, long-lived SSH keys on individual instances. For Ansible-managed instances using the `google.cloud.gcp_compute_instance` or `gcp_compute_instance` modules, the `metadata.enable-oslogin` property must be set to true. Resources missing the `enable-oslogin` metadata key or with a value that does not evaluate to Ansible true will be flagged. Secure configuration example:

```yaml
- name: create instance with OS Login enabled
  google.cloud.gcp_compute_instance:
    name: my-instance
    zone: us-central1-a
    metadata:
      enable-oslogin: true
```

## Compliant Code Examples
```yaml
- name: oslogin-enabled
  google.cloud.gcp_compute_instance:
    metadata:
      enable-oslogin: yes
    zone: us-central1-a
    auth_kind: serviceaccount
- name: oslogin-missing
  google.cloud.gcp_compute_instance:
    metadata:
      startup-script-url: gs:://graphite-playground/bootstrap.sh
      cost-center: '12345'
    zone: us-central1-a
    auth_kind: serviceaccount

```
## Non-Compliant Code Examples
```yaml
- name: oslogin-disabled
  google.cloud.gcp_compute_instance:
    metadata:
      enable-oslogin: no
    zone: us-central1-a
    auth_kind: serviceaccount

```