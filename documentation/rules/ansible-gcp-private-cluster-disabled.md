---
title: "Private cluster disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/private_cluster_disabled"
  id: "ansible-gcp-private-cluster-disabled"
  display_name: "Private cluster disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-private-cluster-disabled{{< /copyable-code >}}

**Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_cluster_module.html)

### Description

GKE clusters must be configured as private to avoid exposing the control plane endpoint and worker nodes to the public internet. Public exposure increases the risk of unauthorized access and lateral movement.

For Ansible resources using `google.cloud.gcp_container_cluster` or `gcp_container_cluster`, the `private_cluster_config` property must be defined with `enable_private_endpoint` and `enable_private_nodes` set to `true`. Resources missing `private_cluster_config`, missing either attribute, or with either attribute set to `false` are flagged.

Secure Ansible configuration example:

```yaml
- name: Create private GKE cluster
  google.cloud.gcp_container_cluster:
    name: my-cluster
    location: us-central1
    private_cluster_config:
      enable_private_nodes: true
      enable_private_endpoint: true
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
    private_cluster_config:
      enable_private_endpoint: yes
      enable_private_nodes: yes

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
    name: my-cluster2
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
    private_cluster_config:
      enable_private_endpoint: yes
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
    private_cluster_config:
      enable_private_nodes: yes
- name: create a cluster4
  google.cloud.gcp_container_cluster:
    name: my-cluster4
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
    private_cluster_config:
      enable_private_endpoint: no
      enable_private_nodes: yes
- name: create a cluster5
  google.cloud.gcp_container_cluster:
    name: my-cluster5
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
    private_cluster_config:
      enable_private_endpoint: yes
      enable_private_nodes: no

```