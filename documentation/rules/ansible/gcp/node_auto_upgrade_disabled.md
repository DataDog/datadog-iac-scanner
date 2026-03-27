---
title: "Node auto-upgrade disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/node_auto_upgrade_disabled"
  id: "d6e10477-2e19-4bcd-b8a8-19c65b89ccdf"
  display_name: "Node auto-upgrade disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Resource Management"
---
## Metadata

**Id:** `d6e10477-2e19-4bcd-b8a8-19c65b89ccdf`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_node_pool_module.html#parameter-management/auto_upgrade)

### Description

Kubernetes node pools must have automatic node upgrades enabled so nodes receive security patches and Kubernetes version updates promptly. This reduces exposure to known vulnerabilities and version drift.

For Ansible tasks using the `google.cloud.gcp_container_node_pool` or `gcp_container_node_pool` modules, the `management.auto_upgrade` property must be defined and set to `true`. Tasks missing the `management` block, missing `management.auto_upgrade`, or with `auto_upgrade` set to `false` are flagged as insecure. Secure configuration example:

```yaml
- name: Create GKE node pool with auto-upgrade
  google.cloud.gcp_container_node_pool:
    name: my-node-pool
    cluster: my-cluster
    zone: us-central1-a
    management:
      auto_upgrade: true
    initial_node_count: 3
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
      auto-repair: yes
      auto_upgrade: yes

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
- name: create a second node pool
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
      auto_repair: yes
- name: create a third node pool
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
      auto_repair: yes
      auto_upgrade: no

```