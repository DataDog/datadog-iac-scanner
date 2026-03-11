---
title: "GKE Legacy Authorization Enabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/gke_legacy_authorization_enabled"
  id: "300a9964-b086-41f7-9378-b6de3ba1c32b"
  display_name: "GKE Legacy Authorization Enabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `300a9964-b086-41f7-9378-b6de3ba1c32b`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_cluster_module.html)

### Description

Legacy Authorization (ABAC) must be disabled on Kubernetes Engine (GKE) clusters because ABAC grants access based on user attributes instead of fine‑grained RBAC rules, which can result in overly broad permissions and increase the risk of unauthorized access or privilege escalation. For Ansible-managed clusters using the `google.cloud.gcp_container_cluster` or `gcp_container_cluster` modules, the `legacy_abac.enabled` property must be set to `false`. This rule flags cluster resources where `legacy_abac.enabled` is `true`; ensure the property is explicitly defined as `false` in your cluster declaration to enforce RBAC. 

Secure configuration example:

```yaml
- name: Create GKE cluster with legacy ABAC disabled
  google.cloud.gcp_container_cluster:
    name: my-cluster
    location: us-central1
    legacy_abac:
      enabled: false
    initial_node_count: 3
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
    legacy_abac:
      enabled: no

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
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
    service_account_file: "/tmp/auth.pem"
    state: present
    legacy_abac:
      enabled: yes

```