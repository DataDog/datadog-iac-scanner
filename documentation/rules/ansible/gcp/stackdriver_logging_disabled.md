---
title: "Stackdriver logging disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/stackdriver_logging_disabled"
  id: "19c9e2a0-fc33-4264-bba1-e3682661e8f7"
  display_name: "Stackdriver logging disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** {{</* copyable-code */>}}19c9e2a0-fc33-4264-bba1-e3682661e8f7{{</* copyable-code */>}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_cluster_module.html)

### Description

GKE clusters must have Cloud Logging (Stackdriver) enabled so cluster control plane and node logs are centrally collected for monitoring, alerting, incident response, and forensic analysis. Without central logging, audit trails and operational diagnostics can be lost or unavailable during security investigations.

For the Ansible GCP modules `google.cloud.gcp_container_cluster` and `gcp_container_cluster`, the `logging_service` property must be defined and must not be set to `"none"` (case-insensitive), since `"none"` disables Cloud Logging. Resources missing `logging_service` or with `logging_service: "none"` are flagged. 

Secure example configuration:

```yaml
- name: Create GKE cluster with logging enabled
  google.cloud.gcp_container_cluster:
    name: my-cluster
    zone: us-central1-a
    logging_service: logging.googleapis.com
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
    logging_service: logging.googleapis.com

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
    logging_service: none

```