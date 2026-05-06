---
title: "COS node image not used"
group_id: "Ansible / GCP"
meta:
  name: "gcp/cos_node_image_not_used"
  id: "be41f891-96b1-4b9d-b74f-b922a918c778"
  display_name: "COS node image not used"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{</* copyable-code */>}}be41f891-96b1-4b9d-b74f-b922a918c778{{</* copyable-code */>}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_node_pool_module.html#parameter-config/image_type)

### Description

GKE node pools should use Container-Optimized OS (COS) images. COS is a Google-managed, hardened OS with automatic security updates and tighter integration with GKE, reducing exposure to unpatched vulnerabilities and kernel-level attack surface.

In Ansible, check tasks using the `google.cloud.gcp_container_node_pool` or `gcp_container_node_pool` modules and ensure the `config.image_type` property is defined and starts with `COS` (case-insensitive). Tasks missing `config.image_type` or with values that do not start with `COS` are flagged.

Secure configuration example:

```yaml
- name: Create GKE node pool with COS image
  google.cloud.gcp_container_node_pool:
    name: my-node-pool
    initial_node_count: 3
    config:
      machine_type: e2-medium
      image_type: COS_CONTAINERD
```

## Compliant Code Examples
```yaml
- name: create a node pool
  google.cloud.gcp_container_node_pool:
    name: my-pool
    initial_node_count: 4
    cluster: '{{ cluster }}'
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present
    config:
      image_type: COS

```

```yaml
- name: create a node pool
  google.cloud.gcp_container_node_pool:
    name: my-pool
    initial_node_count: 4
    cluster: "{{ cluster }}"
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present
    config:
      image_type: COS_CONTAINERD

```
## Non-Compliant Code Examples
```yaml
---
- name: create a node pool
  google.cloud.gcp_container_node_pool:
    name: my-pool
    initial_node_count: 4
    cluster: "{{ cluster }}"
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
    config:
      image_type: WINDOWS_LTSC

```