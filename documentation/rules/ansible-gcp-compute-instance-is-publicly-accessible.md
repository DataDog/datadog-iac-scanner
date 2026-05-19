---
title: "Compute instance is publicly accessible"
group_id: "Ansible / GCP"
meta:
  name: ""gcp/compute_instance_is_publicly_accessible""
  id: "ansible-gcp-compute-instance-is-publicly-accessible"
  display_name: "Compute instance is publicly accessible"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-compute-instance-is-publicly-accessible{{< /copyable-code >}}

**Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_instance_module.html#parameter-network_interfaces/access_configs)

### Description

Compute instances must not be assigned external (public) IP addresses. Public IPs expose instances directly to the internet, increasing the risk of unauthorized access, brute-force attacks, and data exfiltration.

For Ansible Google Cloud compute instance resources (modules `google.cloud.gcp_compute_instance` and `gcp_compute_instance`), ensure the `network_interfaces[].access_configs` property is not defined. Any `network_interfaces` entry containing `access_configs` indicates an external IP is being assigned and is flagged. Remove `access_configs` to prevent automatic external IP allocation and use Cloud NAT, internal load balancers, or bastion hosts for controlled outbound/inbound access instead.

Secure configuration example (no external IP):

```yaml
- name: Create instance without external IP
  google.cloud.gcp_compute_instance:
    name: my-instance
    machine_type: e2-medium
    zone: us-central1-a
    network_interfaces:
      - network: default
        subnetwork: default
        # no access_configs defined -> no external IP assigned
```

## Compliant Code Examples
```yaml
- name: create a instance
  google.cloud.gcp_compute_instance:
    name: test_object
    network_interfaces:
    - network: '{{ network }}'
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: create a instance
  google.cloud.gcp_compute_instance:
    name: test_object
    network_interfaces:
    - network: "{{ network }}"
      access_configs:
      - name: External NAT
        nat_ip: "{{ address }}"
        type: ONE_TO_ONE_NAT
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    state: present

```