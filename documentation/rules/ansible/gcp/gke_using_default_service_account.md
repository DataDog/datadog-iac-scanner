---
title: "GKE using default service account"
group_id: "Ansible / GCP"
meta:
  name: "gcp/gke_using_default_service_account"
  id: "ansible-gcp-gke-using-default-service-account"
  display_name: "GKE using default service account"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Defaults"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-gke-using-default-service-account{{< /copyable-code >}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_cluster_module.html#parameter-node_config/service_account)

### Description

Kubernetes Engine clusters should not use the default node service account. The default account typically has broad permissions, increasing the blast radius if a node is compromised.

For Ansible resources using `google.cloud.gcp_container_cluster` or `gcp_container_cluster`, the `node_config.service_account` property must be defined and set to a dedicated, least-privilege IAM service account (full email address). Resources missing `node_config.service_account` or with a value containing `"default"` are flagged. Use a distinct service account with narrowly scoped IAM roles, for example, `my-sa@PROJECT_ID.iam.gserviceaccount.com`.

Secure configuration example:

```yaml
- name: Create GKE cluster with custom node service account
  google.cloud.gcp_container_cluster:
    name: my-cluster
    location: us-central1
    node_config:
      service_account: my-sa@my-project.iam.gserviceaccount.com
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
      service_account: "{{ myaccount }}"
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a service account
  google.cloud.gcp_iam_service_account:
    name: sa-{{ resource_name.split("-")[-1] }}@graphite-playground.google.com.iam.gserviceaccount.com
    display_name: My Ansible test key
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
  register: myaccount

```
## Non-Compliant Code Examples
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
      service_account: "{{ default }}"
    location: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a service account
  google.cloud.gcp_iam_service_account:
    name: sa-{{ resource_name.split("-")[-1] }}@graphite-playground.google.com.iam.gserviceaccount.com
    display_name: My Ansible test key
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
  register: default

```

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
    service_account_file: "/tmp/auth.pem"
    state: present

```