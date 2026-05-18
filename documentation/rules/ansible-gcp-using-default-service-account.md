---
title: "Using default service account"
group_id: "Ansible / GCP"
meta:
  name: "gcp/using_default_service_account"
  id: "ansible-gcp-using-default-service-account"
  display_name: "Using default service account"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-using-default-service-account{{< /copyable-code >}}

**Provider:** GCP

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_instance_module.html)

### Description

Compute instances must not use the default Google Compute Engine service account. That account often has broad Cloud API privileges, which can lead to unintended privilege escalation or overly permissive access. For Ansible tasks using the `google.cloud.gcp_compute_instance` or `gcp_compute_instance` module with `auth_kind: serviceaccount`, the `service_account_email` property must be defined, must be a non-empty string containing an `@`, and must not reference a default Compute Engine service account (values containing `@developer.gserviceaccount.com`). Resources missing `service_account_email`, with an empty value, lacking an `@` character, or using a default developer service account are flagged.

Secure example:

```yaml
- name: Create instance with explicit service account
  google.cloud.gcp_compute_instance:
    name: my-instance
    auth_kind: serviceaccount
    service_account_email: my-sa@my-project.iam.gserviceaccount.com
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
    service_account_email: admin@admin.com
    state: present

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: create a instance1
  google.cloud.gcp_compute_instance:
    name: test_object1
    machine_type: n1-standard-1
    disks:
    - auto_delete: 'true'
      boot: 'true'
      source: "{{ disk }}"
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
    - network: "{{ network }}"
      access_configs:
      - name: External NAT
        nat_ip: "{{ address }}"
        type: ONE_TO_ONE_NAT
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    state: present
- name: create a instance2
  google.cloud.gcp_compute_instance:
    name: test_object2
    machine_type: n1-standard-1
    disks:
    - auto_delete: 'true'
      boot: 'true'
      source: "{{ disk }}"
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
    - network: "{{ network }}"
      access_configs:
      - name: External NAT
        nat_ip: "{{ address }}"
        type: ONE_TO_ONE_NAT
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_email: ""
    state: present
- name: create a instance3
  google.cloud.gcp_compute_instance:
    name: test_object3
    machine_type: n1-standard-1
    disks:
    - auto_delete: 'true'
      boot: 'true'
      source: "{{ disk }}"
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
    - network: "{{ network }}"
      access_configs:
      - name: External NAT
        nat_ip: "{{ address }}"
        type: ONE_TO_ONE_NAT
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_email: "admin"
    state: present
- name: create a instance4
  google.cloud.gcp_compute_instance:
    name: test_object4
    machine_type: n1-standard-1
    disks:
    - auto_delete: 'true'
      boot: 'true'
      source: "{{ disk }}"
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
    - network: "{{ network }}"
      access_configs:
      - name: External NAT
        nat_ip: "{{ address }}"
        type: ONE_TO_ONE_NAT
    zone: us-central1-a
    project: test_project
    auth_kind: serviceaccount
    service_account_email: "admin@developer.gserviceaccount.com"
    state: present

```