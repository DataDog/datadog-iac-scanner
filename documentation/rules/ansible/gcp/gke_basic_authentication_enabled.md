---
title: "GKE basic authentication enabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/gke_basic_authentication_enabled"
  id: "ansible-gcp-gke-basic-authentication-enabled"
  display_name: "GKE basic authentication enabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-gke-basic-authentication-enabled{{< /copyable-code >}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_cluster_module.html)

### Description

Disabling GKE basic authentication is required because an embedded cluster username and password can be leaked or abused to gain direct admin access to the Kubernetes API, bypassing IAM and RBAC protections.

The Ansible GKE resources `google.cloud.gcp_container_cluster` and `gcp_container_cluster` must include a `master_auth` block with both `username` and `password` set to empty strings to indicate basic auth is disabled. Resources that omit `master_auth`, omit either `username` or `password`, or provide non-empty values are flagged. 

Secure configuration example:

```yaml
- name: Create GKE cluster with basic auth disabled
  google.cloud.gcp_container_cluster:
    name: my-cluster
    master_auth:
      username: ""
      password: ""
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: create a cluster
  google.cloud.gcp_container_cluster:
    name: my-cluster
    initial_node_count: 2
    master_auth:
      username: ''
      password: ''
    node_config:
      machine_type: n1-standard-4
      disk_size_gb: 500
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: create a cluster1
  google.cloud.gcp_container_cluster:
    name: my-cluster1
    initial_node_count: 2
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
      password: ""
    node_config:
      machine_type: n1-standard-4
      disk_size_gb: 500
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a cluster3
  google.cloud.gcp_container_cluster:
    name: my-cluster3
    initial_node_count: 2
    master_auth:
      username: ""
    node_config:
      machine_type: n1-standard-4
      disk_size_gb: 500
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a cluster4
  google.cloud.gcp_container_cluster:
    name: my-cluster4
    initial_node_count: 2
    master_auth:
      username: cluster_admin
      password: ""
    node_config:
      machine_type: n1-standard-4
      disk_size_gb: 500
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a cluster5
  google.cloud.gcp_container_cluster:
    name: my-cluster5
    initial_node_count: 2
    master_auth:
      username: ""
      password: my-secret-password
    node_config:
      machine_type: n1-standard-4
      disk_size_gb: 500
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```