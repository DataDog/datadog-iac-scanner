---
title: "Shielded VM disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/shielded_vm_disabled"
  id: "ansible-gcp-shielded-vm-disabled"
  display_name: "Shielded VM disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `ansible-gcp-shielded-vm-disabled`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_instance_module.html)

### Description

Compute instances must have Shielded VM features enabled to protect boot integrity and prevent or detect kernel and firmware tampering.

For Ansible resources using `google.cloud.gcp_compute_instance` or `gcp_compute_instance`, the `shielded_instance_config` property must be defined with `enable_secure_boot`, `enable_vtpm`, and `enable_integrity_monitoring` set to `true`. Resources missing `shielded_instance_config` or with any of these attributes undefined or set to `false` are flagged.

Secure configuration example:

```yaml
- name: Create GCP compute instance with Shielded VM enabled
  google.cloud.gcp_compute_instance:
    name: my-instance
    machine_type: e2-medium
    zone: us-central1-a
    shielded_instance_config:
      enable_secure_boot: true
      enable_vtpm: true
      enable_integrity_monitoring: true
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: create a instance
  google.cloud.gcp_compute_instance:
    name: test_object
    machine_type: n1-standard-1
    disks:
    - auto_delete: 'true'
      boot: 'true'
      source: '{{ disk }}'
    - auto_delete: 'true'
      interface: NVME
      type: SCRATCH
      initialize_params:
        disk_type: local-ssd
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
    shielded_instance_config:
      enable_integrity_monitoring: yes
      enable_secure_boot: yes
      enable_vtpm: yes

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: create a instance1
  google.cloud.gcp_compute_instance:
    name: test_object1
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
- name: create a instance2
  google.cloud.gcp_compute_instance:
    name: test_object2
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
    shielded_instance_config:
      enable_secure_boot: yes
      enable_vtpm: yes
- name: create a instance3
  google.cloud.gcp_compute_instance:
    name: test_object3
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
    shielded_instance_config:
      enable_integrity_monitoring: yes
      enable_vtpm: yes
- name: create a instance4
  google.cloud.gcp_compute_instance:
    name: test_object4
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
    shielded_instance_config:
      enable_integrity_monitoring: yes
      enable_secure_boot: yes
- name: create a instance5
  google.cloud.gcp_compute_instance:
    name: test_object5
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
    shielded_instance_config:
      enable_integrity_monitoring: no
      enable_secure_boot: yes
      enable_vtpm: yes
- name: create a instance6
  google.cloud.gcp_compute_instance:
    name: test_object6
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
    shielded_instance_config:
      enable_integrity_monitoring: yes
      enable_secure_boot: no
      enable_vtpm: yes
- name: create a instance7
  google.cloud.gcp_compute_instance:
    name: test_object7
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
    shielded_instance_config:
      enable_integrity_monitoring: yes
      enable_secure_boot: yes
      enable_vtpm: no

```