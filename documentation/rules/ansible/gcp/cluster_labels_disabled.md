---
title: "Cluster labels disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/cluster_labels_disabled"
  id: "fbe9b2d0-a2b7-47a1-a534-03775f3013f7"
  display_name: "Cluster labels disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{</* copyable-code */>}}fbe9b2d0-a2b7-47a1-a534-03775f3013f7{{</* copyable-code */>}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_cluster_module.html)

### Description

Kubernetes clusters should include resource labels to ensure assets are identifiable and support inventory, policy targeting, and incident response. For Ansible-managed GKE clusters using the `google.cloud.gcp_container_cluster` or `gcp_container_cluster` modules, the `resource_labels` property must be defined and contain at least one key/value pair. Tasks missing the `resource_labels` property or with it set to an empty value (for example, an empty string) are flagged.

Secure configuration example:

```yaml
- name: Create GKE cluster with labels
  google.cloud.gcp_container_cluster:
    name: my-cluster
    resource_labels:
      env: prod
      owner: team-a
```

## Compliant Code Examples
```yaml
- name: create a cluster
  google.cloud.gcp_container_cluster:
    name: my-cluster
    initial_node_count: 2
    master_auth:
      username: cluster_admin
      password: my-secret-password
    node_config:
      machine_type: n1-standard-4
      disk_size_gb: 500
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present
    resource_labels: label1

```
## Non-Compliant Code Examples
```yaml
- name: create a cluster1
  google.cloud.gcp_container_cluster:
    name: my-cluster1
    initial_node_count: 2
    master_auth:
      username: cluster_admin
      password: my-secret-password
    node_config:
      machine_type: n1-standard-4
      disk_size_gb: 500
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a cluster2
  google.cloud.gcp_container_cluster:
    name: my-cluster3
    initial_node_count: 2
    master_auth:
      username: cluster_admin
      password: my-secret-password
    node_config:
      machine_type: n1-standard-4
      disk_size_gb: 500
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
    resource_labels:
- name: create a cluster3
  google.cloud.gcp_container_cluster:
    name: my-cluster3
    initial_node_count: 2
    master_auth:
      username: cluster_admin
      password: my-secret-password
    node_config:
      machine_type: n1-standard-4
      disk_size_gb: 500
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
    resource_labels: ""

```