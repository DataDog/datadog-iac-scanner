---
title: "Client certificate disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/client_certificate_disabled"
  id: "ansible-gcp-client-certificate-disabled"
  display_name: "Client certificate disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-client-certificate-disabled{{< /copyable-code >}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_cluster_module.html)

### Description

Client certificate authentication for the Kubernetes control plane ensures administrators authenticate with strong cryptographic credentials, reducing reliance on weaker or shared credentials that can lead to unauthorized control-plane access.

For Ansible GCP Container Cluster resources (`google.cloud.gcp_container_cluster` and `gcp_container_cluster`), the `master_auth` object must include `client_certificate_config` with `issue_client_certificate: true`. Resources that omit `master_auth`, omit `client_certificate_config`, or set `issue_client_certificate` to `false` are flagged. 

Secure configuration example for an Ansible task:

```yaml
- name: Create GKE cluster with client certificate enabled
  google.cloud.gcp_container_cluster:
    name: my-cluster
    master_auth:
      client_certificate_config:
        issue_client_certificate: true
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
      client_certificate_config:
        issue_client_certificate: yes
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
- name: create a cluster3
  google.cloud.gcp_container_cluster:
    name: my-cluster3
    initial_node_count: 2
    master_auth:
      username: cluster_admin
      password: my-secret-password
      client_certificate_config:
        issue_client_certificate: no
    node_config:
      machine_type: n1-standard-4
      disk_size_gb: 500
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```