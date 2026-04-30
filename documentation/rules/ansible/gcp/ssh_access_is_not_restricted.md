---
title: "SSH access is not restricted"
group_id: "Ansible / GCP"
meta:
  name: "gcp/ssh_access_is_not_restricted"
  id: "ansible-gcp-ssh-access-is-not-restricted"
  display_name: "SSH access is not restricted"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ansible-gcp-ssh-access-is-not-restricted`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_firewall_module.html)

### Description

Allowing SSH (port 22) from the public Internet exposes instances to brute-force attacks and unauthorized access. This can lead to credential compromise and lateral movement across your network.

In Ansible tasks using the `google.cloud.gcp_compute_firewall` or `gcp_compute_firewall` modules, this rule flags ingress rules where `source_ranges` includes `0.0.0.0/0` or `::/0` and an `allowed` entry specifies port `22` (for example, `allowed[].ip_protocol='tcp'` and `allowed[].ports` contains `22`).

Restrict SSH access to specific trusted CIDR ranges, place SSH behind a bastion host or VPN, or use identity-aware access methods instead of allowing unrestricted Internet access.

Secure example restricting SSH to a single admin IP:

```yaml
- name: allow-ssh-from-admin
  google.cloud.gcp_compute_firewall:
    name: allow-ssh-from-admin
    network: default
    direction: INGRESS
    source_ranges:
      - 203.0.113.5/32
    allowed:
      - ip_protocol: tcp
        ports: ['22']
```

## Compliant Code Examples
```yaml
- name: ssh_restricted
  google.cloud.gcp_compute_firewall:
    name: test_object
    denied:
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
    service_account_file: /tmp/auth.pem
    state: present
    source_ranges:
    - 0.0.0.0

```
## Non-Compliant Code Examples
```yaml
- name: ssh_unrestricted
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
    source_ranges:
    - "0.0.0.0/0"

```