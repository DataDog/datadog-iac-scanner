---
title: "Stackdriver monitoring disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/stackdriver_monitoring_disabled"
  id: "20dcd953-a8b8-4892-9026-9afa6d05a525"
  display_name: "Stackdriver monitoring disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `20dcd953-a8b8-4892-9026-9afa6d05a525`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_cluster_module.html)

### Description

GKE clusters must have Cloud Monitoring (Stackdriver) enabled to provide observability and support timely incident detection and response. Disabling monitoring removes metrics and logs needed for alerting, troubleshooting, and forensic analysis.

For Ansible resources using the `google.cloud.gcp_container_cluster` or `gcp_container_cluster` modules, the `monitoring_service` property must be defined and must not be set to `'none'`. Resources that omit `monitoring_service` or explicitly set `monitoring_service: 'none'` are flagged.

Secure configuration example:

```yaml
- name: Create GKE cluster with monitoring enabled
  google.cloud.gcp_container_cluster:
    name: my-cluster
    monitoring_service: monitoring.googleapis.com/kubernetes
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
    monitoring_service: monitoring.googleapis.com

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
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
    monitoring_service: none

```