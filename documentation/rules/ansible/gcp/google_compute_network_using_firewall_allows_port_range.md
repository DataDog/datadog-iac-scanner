---
title: "Google Compute network using firewall rule that allows port range"
group_id: "Ansible / GCP"
meta:
  name: "gcp/google_compute_network_using_firewall_allows_port_range"
  id: "7289eebd-a477-4064-8ad4-3c044bd70b00"
  display_name: "Google Compute network using firewall rule that allows port range"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{</* copyable-code */>}}7289eebd-a477-4064-8ad4-3c044bd70b00{{</* copyable-code */>}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_firewall_module.html#parameter-allowed)

### Description

Compute network firewall rules must not permit ingress using broad port ranges because ranges increase attack surface, make it harder to apply least privilege, and can unintentionally expose multiple services.

This check inspects Ansible tasks using the `google.cloud.gcp_compute_firewall` or `gcp_compute_firewall` modules and flags ingress rules where `allowed[].ports[]` entries are numeric ranges matching the `start-end` pattern (for example, `"8000-9000"`). The rule does not match the literal `"0-65535"`.

The check applies when the firewall's `network` references a compute network task, meaning the firewall `network` equals the compute network's registered name. To resolve, specify explicit single ports or a minimal list of ports and scope ingress with specific source ranges or target tags.

Secure example with explicit single ports:

```yaml
- name: Create restricted firewall rule
  google.cloud.gcp_compute_firewall:
    name: allow-ssh
    network: "{{ my_network.registered_name }}"
    direction: INGRESS
    allowed:
      - IPProtocol: tcp
        ports:
          - "22"
    sourceRanges:
      - "203.0.113.0/24"
```

## Compliant Code Examples
```yaml
- name: create a firewall
  google.cloud.gcp_compute_firewall:
    name: test_object
    allowed:
    - ip_protocol: tcp
      ports:
      - '22'
    target_tags:
    - test-ssh-server
    - staging-ssh-server
    source_tags:
    - test-ssh-clients
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
    network: "{{ my_network }}"
- name: create a network
  google.cloud.gcp_compute_network:
    name: test_object
    auto_create_subnetworks: 'true'
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
  register: my_network

```
## Non-Compliant Code Examples
```yaml
- name: create a firewall2
  google.cloud.gcp_compute_firewall:
    name: test_object
    allowed:
    - ip_protocol: tcp
      ports:
      - '20-1000'
    target_tags:
    - test-ssh-server
    - staging-ssh-server
    source_tags:
    - test-ssh-clients
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
    network: "{{ my_network2 }}"
- name: create a network2
  google.cloud.gcp_compute_network:
    name: test_object
    auto_create_subnetworks: 'true'
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
  register: my_network2

```