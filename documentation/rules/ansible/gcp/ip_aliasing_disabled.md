---
title: "IP aliasing disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/ip_aliasing_disabled"
  id: "ed672a9f-fbf0-44d8-a47d-779501b0db05"
  display_name: "IP aliasing disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ed672a9f-fbf0-44d8-a47d-779501b0db05{{< /copyable-code >}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_cluster_module.html)

### Description

Kubernetes clusters must enable Alias IP ranges so pods use VPC-native networking. This prevents pod IP address conflicts and enables VPC features such as network policy enforcement and private IP addressing.

For Ansible-managed GKE clusters using the `google.cloud.gcp_container_cluster` (or `gcp_container_cluster`) module, the `ip_allocation_policy` property must be defined and its `use_ip_aliases` subproperty must be set to `true` (Ansible: `yes`). Resources missing `ip_allocation_policy`, missing `use_ip_aliases`, or with `use_ip_aliases` set to `false` are flagged. Secure configuration example:

```yaml
- name: create gke cluster with alias IPs
  google.cloud.gcp_container_cluster:
    name: my-cluster
    location: us-central1
    ip_allocation_policy:
      use_ip_aliases: yes
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
    ip_allocation_policy:
      create_subnetwork: no
      use_ip_aliases: yes

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
    ip_allocation_policy:
      create_subnetwork: no
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
    ip_allocation_policy:
      create_subnetwork: no
      use_ip_aliases: no

```