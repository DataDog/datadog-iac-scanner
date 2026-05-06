---
title: "Google Compute network using default firewall rule"
group_id: "Ansible / GCP"
meta:
  name: "gcp/google_compute_network_using_default_firewall_rule"
  id: "29b8224a-60e9-4011-8ac2-7916a659841f"
  display_name: "Google Compute network using default firewall rule"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{</* copyable-code */>}}29b8224a-60e9-4011-8ac2-7916a659841f{{</* copyable-code */>}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_firewall_module.html#parameter-name)

### Description

Using a default firewall rule named "default" can expose a Compute Network to overly permissive ingress or egress, violating least-privilege network segmentation and increasing the risk of unauthorized access and lateral movement.

This rule flags Ansible tasks using the `google.cloud.gcp_compute_firewall` or `gcp_compute_firewall` module where the firewall `name` contains "default" and the `network` property attaches to a network created or registered by a prior `google.cloud.gcp_compute_network` or `gcp_compute_network` task. Specifically, firewall tasks with `name` including "default" and `network` set to the registered network value (for example, `network: "{{ <compute_task.register> }}"`) are flagged.

Replace default rules with explicit, least-privilege firewall rules that specify precise allowed ports and source ranges, or reference the intended network and rule names explicitly rather than reusing the default.

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
    name: default
    allowed:
    - ip_protocol: tcp
      ports:
      - '22'
    state: present
    network: "{{ my_network2 }}"
- name: create a network2
  google.cloud.gcp_compute_network:
    name: test_object2
    auto_create_subnetworks: 'true'
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
  register: my_network2

```