---
title: "Google Compute network using firewall rule that allows all ports"
group_id: "Ansible / GCP"
meta:
  name: ""gcp/google_compute_network_using_firewall_rule_allows_all_ports""
  id: "ansible-gcp-google-compute-network-using-firewall-rule-allows-all-ports"
  display_name: "Google Compute network using firewall rule that allows all ports"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-google-compute-network-using-firewall-rule-allows-all-ports{{< /copyable-code >}}

**Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_firewall_module.html#parameter-allowed)

### Description

Allowing ingress on all ports (0-65535) greatly increases attack surface by exposing every service port to network scanning and exploitation. This can lead to unauthorized access, lateral movement, and easier compromise of instances.

This rule flags Ansible tasks using the `google.cloud.gcp_compute_firewall` or `gcp_compute_firewall` module where the rule is ingress and the `allowed` entry contains `ports: ["0-65535"]` for a firewall associated with a compute network referenced by a preceding `google.cloud.gcp_compute_network`/`gcp_compute_network` task.

The `allowed.ports` property must not include `"0-65535"`. Instead, specify explicit ports or narrow ranges (for example `"80"`, `"443"`, or `"1024-2048"`) and restrict access with appropriate `sourceRanges` or other selectors. 

Secure example (allow only HTTP/HTTPS from a limited source range):

```yaml
- name: Allow HTTP and HTTPS from internal range
  google.cloud.gcp_compute_firewall:
    name: allow-web
    network: "{{ my_network }}"
    direction: INGRESS
    allowed:
      - IPProtocol: tcp
        ports: ["80", "443"]
    sourceRanges: ["10.0.0.0/8"]
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
      - '0-65535'
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