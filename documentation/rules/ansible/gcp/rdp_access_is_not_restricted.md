---
title: "RDP access is not restricted"
group_id: "Ansible / GCP"
meta:
  name: "gcp/rdp_access_is_not_restricted"
  id: "ansible-gcp-rdp-access-is-not-restricted"
  display_name: "RDP access is not restricted"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ansible-gcp-rdp-access-is-not-restricted`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_firewall_module.html)

### Description

Allowing unrestricted RDP (TCP port 3389) ingress exposes hosts to automated brute-force attacks and unauthorized remote access. This rule inspects Ansible `google.cloud.gcp_compute_firewall` and `gcp_compute_firewall` tasks and flags ingress rules whose `source_ranges` include unrestricted CIDRs (for example `0.0.0.0/0` or `::/0`) and whose `allowed` entries include port `3389` (typically `ip_protocol: tcp`).

The `allowed` property must not include port `3389` for rules that permit unrestricted source ranges. Either remove or disable RDP on the firewall, or restrict `source_ranges` to trusted CIDRs. Consider using a bastion host, VPN, or identity-based access (IAP/SSM) instead of direct RDP. Resources where `direction` is ingress, `source_ranges` contains an unrestricted CIDR, and `allowed[].ports` contains `"3389"` are flagged.

Secure example that restricts RDP to a corporate CIDR:

```yaml
- name: allow-rdp-from-corporate
  google.cloud.gcp_compute_firewall:
    name: allow-rdp-corp
    network: default
    direction: INGRESS
    source_ranges:
      - 10.0.0.0/8
    allowed:
      - ip_protocol: tcp
        ports:
          - "3389"
```

## Compliant Code Examples
```yaml
- name: create a firewall
  google.cloud.gcp_compute_firewall:
    name: test_object
    allowed:
    - ip_protocol: tcp
      ports:
      - '80'
    target_tags:
    - test-ssh-server
    - staging-ssh-server
    source_tags:
    - test-ssh-clients
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: rdp_in_range
  google.cloud.gcp_compute_firewall:
    name: test_object
    source_ranges:
      - "0.0.0.0/0"
    allowed:
      - ip_protocol: tcp
        ports:
          - "22"
          - "80"
          - "8080"
          - "2000-4000"
    target_tags:
      - test-ssh-server
      - staging-ssh-server
    source_tags:
      - test-ssh-clients
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: rdp_in_port
  google.cloud.gcp_compute_firewall:
    name: test_object
    source_ranges:
      - "0.0.0.0/0"
    allowed:
      - ip_protocol: tcp
        ports:
          - "22"
          - "80"
          - "3389"
    target_tags:
      - test-ssh-server
      - staging-ssh-server
    source_tags:
      - test-ssh-clients
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```