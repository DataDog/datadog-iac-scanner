---
title: "IP forwarding enabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/ip_forwarding_enabled"
  id: "ansible-gcp-ip-forwarding-enabled"
  display_name: "IP forwarding enabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ansible-gcp-ip-forwarding-enabled`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_instance_module.html)

### Description

Compute instances must not have IP forwarding enabled. Allowing an instance to forward packets can be used to intercept, relay, or spoof network traffic. This enables lateral movement or bypassing of network security controls. For Google Cloud Compute instances managed with the Ansible modules `google.cloud.gcp_compute_instance` or `gcp_compute_instance`, the `can_ip_forward` property must be defined and set to `false` (not true/yes).

Instances with `can_ip_forward` set to `true` or where the property is omitted are flagged. Only enable IP forwarding when strictly necessary, and document justification and compensating controls such as restrictive firewall rules and isolated network segments.

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: create a instance
  google.cloud.gcp_compute_instance:
    name: test_object
    machine_type: n1-standard-1
    metadata:
      startup-script-url: gs:://graphite-playground/bootstrap.sh
      cost-center: '12345'
    labels:
      environment: production
    network_interfaces:
    - network: '{{ network }}'
      access_configs:
      - name: External NAT
        nat_ip: '{{ address }}'
        type: ONE_TO_ONE_NAT
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present
    can_ip_forward: no

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: create a instance
  google.cloud.gcp_compute_instance:
    name: test_object
    machine_type: n1-standard-1
    metadata:
      startup-script-url: gs:://graphite-playground/bootstrap.sh
      cost-center: '12345'
    labels:
      environment: production
    network_interfaces:
    - network: "{{ network }}"
      access_configs:
      - name: External NAT
        nat_ip: "{{ address }}"
        type: ONE_TO_ONE_NAT
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
    can_ip_forward: yes

```