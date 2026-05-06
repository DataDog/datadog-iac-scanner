---
title: "Google container node pool auto repair disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/google_container_node_pool_auto_repair_disabled"
  id: "d58c6f24-3763-4269-9f5b-86b2569a003b"
  display_name: "Google container node pool auto repair disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{</* copyable-code */>}}d58c6f24-3763-4269-9f5b-86b2569a003b{{</* copyable-code */>}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_node_pool_module.html)

### Description

Node pools must have automatic node repair enabled so unhealthy or failing nodes are remediated automatically, reducing the risk of prolonged downtime and inconsistent cluster state.

For Ansible GKE node pool resources (modules `google.cloud.gcp_container_node_pool` and `gcp_container_node_pool`), the `management` block must be defined and its `auto_repair` property set to `true`. Tasks missing the `management` block or with `management.auto_repair` set to `false` are flagged. 

Secure configuration example:

```yaml
- name: Create GKE node pool with auto repair enabled
  google.cloud.gcp_container_node_pool:
    name: my-node-pool
    cluster: my-cluster
    location: us-central1
    initial_node_count: 3
    management:
      auto_repair: true
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
    management:
      auto_repair: yes

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
    management:
      auto_repair: true

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
    management:
      auto_repair: no

- name: create a node pool2
  google.cloud.gcp_container_node_pool:
    name: my-pool
    initial_node_count: 4
    cluster: "{{ cluster }}"
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
    management:
      auto_repair: false

- name: create a node pool3
  google.cloud.gcp_container_node_pool:
    name: my-pool
    initial_node_count: 4
    cluster: "{{ cluster }}"
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```