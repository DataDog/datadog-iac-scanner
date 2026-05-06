---
title: "Network policy disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/network_policy_disabled"
  id: "98e04ca0-34f5-4c74-8fec-d2e611ce2790"
  display_name: "Network policy disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{</* copyable-code */>}}98e04ca0-34f5-4c74-8fec-d2e611ce2790{{</* copyable-code */>}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_cluster_module.html)

### Description

Kubernetes Engine clusters must have network policy enabled to enforce pod-to-pod network segmentation and limit lateral movement. Without it, workloads can communicate unrestricted and a compromised pod could access other services or sensitive data.

For Ansible-managed GKE clusters using `google.cloud.gcp_container_cluster` or `gcp_container_cluster`, the `network_policy.enabled` property must be `true` and `addons_config.network_policy_config.disabled` must be `false`. Resources missing the `network_policy` or `addons_config.network_policy_config` blocks, or with `network_policy.enabled` set to `false` or `addons_config.network_policy_config.disabled` set to `true`, are flagged as misconfigured.

Secure Ansible configuration example:

```yaml
- name: Create GKE cluster with Network Policy enabled
  google.cloud.gcp_container_cluster:
    name: my-cluster
    location: us-central1
    network_policy:
      enabled: true
    addons_config:
      network_policy_config:
        disabled: false
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
    network_policy:
      enabled: yes
    addons_config:
      network_policy_config:
        disabled: no

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
    addons_config:
      network_policy_config:
        disabled: false
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
    network_policy:
      enabled: yes
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
    network_policy:
      enabled: yes
    addons_config:
      horizontal_pod_autoscaling:
        disabled: yes
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
    network_policy:
      enabled: no
    addons_config:
      network_policy_config:
        disabled: no
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
    network_policy:
      enabled: yes
    addons_config:
      network_policy_config:
        disabled: yes

```