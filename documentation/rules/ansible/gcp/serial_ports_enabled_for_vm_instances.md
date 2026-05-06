---
title: "Serial ports are enabled for VM instances"
group_id: "Ansible / GCP"
meta:
  name: "gcp/serial_ports_enabled_for_vm_instances"
  id: "c6fc6f29-dc04-46b6-99ba-683c01aff350"
  display_name: "Serial ports are enabled for VM instances"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{</* copyable-code */>}}c6fc6f29-dc04-46b6-99ba-683c01aff350{{</* copyable-code */>}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_instance_module.html)

### Description

Enabling the serial console on Google Compute Engine VMs grants low-level interactive access to the instance console. This can bypass network and SSH controls, allowing actors who know project or instance details to interact with or tamper with the VM.

In Ansible, check tasks using `google.cloud.gcp_compute_instance` or `gcp_compute_instance` and ensure the `metadata.serial-port-enable` property is either undefined or explicitly set to `false`. Tasks with `metadata.serial-port-enable: true` are flagged. Remediate by removing the metadata key or setting it to `false`.

Secure Ansible example:

```yaml
- name: Create GCE instance with serial port disabled
  google.cloud.gcp_compute_instance:
    name: my-vm
    machine_type: e2-medium
    metadata:
      "serial-port-enable": false
```

## Compliant Code Examples
```yaml
- name: serial_disabled
  google.cloud.gcp_compute_instance:
    name: serial-disabled-instance
    metadata:
      serial-port-enabled: no
    zone: us-central1-a
    auth_kind: serviceaccount
- name: serial_undefined
  google.cloud.gcp_compute_instance:
    name: serial-undefined-instance
    metadata:
      startup-script-url: gs:://graphite-playground/bootstrap.sh
      cost-center: '12345'
    zone: us-central1-a
    auth_kind: serviceaccount

```
## Non-Compliant Code Examples
```yaml
- name: serial_enabled
  google.cloud.gcp_compute_instance:
    name: serial-enabled-instance
    metadata:
      serial-port-enable: yes
    zone: us-central1-a
    auth_kind: serviceaccount

```