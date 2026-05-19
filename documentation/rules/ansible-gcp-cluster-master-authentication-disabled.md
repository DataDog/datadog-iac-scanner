---
title: "Cluster master authentication disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/cluster_master_authentication_disabled"
  id: "ansible-gcp-cluster-master-authentication-disabled"
  display_name: "Cluster master authentication disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-cluster-master-authentication-disabled{{< /copyable-code >}}

**Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_cluster_module.html)

### Description

Kubernetes Engine clusters must have master authentication credentials defined so control plane access is not left unauthenticated or ambiguous. This ensures administrative access is explicit and auditable.

For Ansible GKE cluster resources using the `google.cloud.gcp_container_cluster` or `gcp_container_cluster` modules, the `master_auth` property must be present and its `username` and `password` subproperties must be defined and non-empty strings. This rule flags resources where `master_auth` is undefined or null, or where `master_auth.username` or `master_auth.password` are undefined, null, or empty. If you use alternative authentication mechanisms, ensure they are explicitly configured. Otherwise, provide non-empty credentials so the cluster admin account is not left unspecified.

Secure configuration example for an Ansible task:

```yaml
- name: Create GKE cluster with master auth
  google.cloud.gcp_container_cluster:
    name: my-cluster
    zone: us-central1
    master_auth:
      username: admin
      password: "{{ gke_admin_password }}"
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
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
      password: my-secret-password
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
      username: cluster_admin
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
      username:
      password: my-secret-password
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
      username: cluster_admin
      password:
    node_config:
      machine_type: n1-standard-4
      disk_size_gb: 500
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```