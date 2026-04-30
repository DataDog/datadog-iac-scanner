---
title: "Google Compute subnetwork with Private Google Access disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/google_compute_subnetwork_with_private_google_access_disabled"
  id: "ansible-gcp-google-compute-subnetwork-with-private-google-access-disabled"
  display_name: "Google Compute subnetwork with Private Google Access disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ansible-gcp-google-compute-subnetwork-with-private-google-access-disabled`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_subnetwork_module.html#parameter-private_ip_google_access)

### Description

Subnetworks must have Private Google Access enabled so VM instances with only internal IPs can reach Google APIs and services over Google's internal network. Without Private Google Access, operators may assign external IPs or route traffic over the public internet, increasing attack surface and the risk of data exposure or network-based attacks.

For Ansible resources using the google.cloud.gcp_compute_subnetwork or gcp_compute_subnetwork modules, the `private_ip_google_access` property must be defined and set to `yes`. Tasks missing this property or with `private_ip_google_access` not equal to `yes` are flagged.

Secure Ansible example:

```yaml
- name: Create subnetwork with Private Google Access enabled
  google.cloud.gcp_compute_subnetwork:
    name: my-subnet
    region: us-central1
    ip_cidr_range: 10.0.0.0/24
    network: my-vpc
    private_ip_google_access: yes
```

## Compliant Code Examples
```yaml
- name: create a subnetwork3
  google.cloud.gcp_compute_subnetwork:
    name: ansiblenet
    region: us-west1
    network: "{{ network }}"
    ip_cidr_range: 172.16.0.0/16
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    private_ip_google_access: yes
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: create a subnetwork2
  google.cloud.gcp_compute_subnetwork:
    name: ansiblenet
    region: us-west1
    network: "{{ network }}"
    ip_cidr_range: 172.16.0.0/16
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    private_ip_google_access: no
    state: present

```

```yaml
- name: create a subnetwork
  google.cloud.gcp_compute_subnetwork:
    name: ansiblenet
    region: us-west1
    network: "{{ network }}"
    ip_cidr_range: 172.16.0.0/16
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```