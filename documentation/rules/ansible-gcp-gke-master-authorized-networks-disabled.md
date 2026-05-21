---
title: "GKE master authorized networks disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/gke_master_authorized_networks_disabled"
  id: "ansible-gcp-gke-master-authorized-networks-disabled"
  display_name: "GKE master authorized networks disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-gke-master-authorized-networks-disabled{{< /copyable-code >}}

**Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_container_cluster_module.html#parameter-master_authorized_networks_config/enabled)

### Description

GKE clusters must enable master authorized networks to restrict access to the Kubernetes control plane to trusted network ranges. Without this restriction, unauthorized or network-based access could lead to cluster compromise.

For Ansible resources using `google.cloud.gcp_container_cluster` or `gcp_container_cluster`, the `master_authorized_networks_config` property must be defined and its `enabled` field set to `true`. Resources missing `master_authorized_networks_config` or with `master_authorized_networks_config.enabled` set to `false` are flagged as insecure. Optionally, include CIDR entries to specify allowed client networks via `master_authorized_networks_config.cidr_blocks`.

Secure Ansible example:

```yaml
- name: Create secure GKE cluster with master authorized networks
  google.cloud.gcp_container_cluster:
    name: my-cluster
    location: us-central1
    master_authorized_networks_config:
      enabled: true
      cidr_blocks:
        - cidr_block: 203.0.113.0/24
          display_name: office-network
```

## Compliant Code Examples
```yaml
- name: create a cluster
  google.cloud.gcp_container_cluster:
    name: my-cluster
    initial_node_count: 2
    location: us-central1-a
    auth_kind: serviceaccount
    master_authorized_networks_config:
      cidr_blocks:
      - cidr_block: 192.0.2.0/24
      enabled: yes
    state: present

```
## Non-Compliant Code Examples
```yaml
---
- name: create a cluster
  google.cloud.gcp_container_cluster:
    name: my-cluster
    location: us-central1-a
    auth_kind: serviceaccount
    master_authorized_networks_config:
      cidr_blocks:
        - cidr_block: 192.0.2.0/24
      enabled: no
    state: present
- name: create a second cluster
  google.cloud.gcp_container_cluster:
    name: my-second-cluster
    location: us-central1-a
    auth_kind: serviceaccount
    master_authorized_networks_config:
      cidr_blocks:
        - cidr_block: 192.0.2.0/24
    state: present
- name: create a third cluster
  google.cloud.gcp_container_cluster:
    name: my-third-cluster
    location: us-central1-a
    auth_kind: serviceaccount
    state: present

```