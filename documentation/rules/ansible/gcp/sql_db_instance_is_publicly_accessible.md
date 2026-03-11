---
title: "SQL DB Instance Publicly Accessible"
group_id: "Ansible / GCP"
meta:
  name: "gcp/sql_db_instance_is_publicly_accessible"
  id: "7d7054c0-3a52-4e9b-b9ff-cbfe16a2378b"
  display_name: "SQL DB Instance Publicly Accessible"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `7d7054c0-3a52-4e9b-b9ff-cbfe16a2378b`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** Critical

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_sql_instance_module.html)

### Description

Cloud SQL instances must not be publicly accessible because allowing access from 0.0.0.0/0 or enabling public IPv4 without restricted networks exposes databases to unauthorized access and data exfiltration. For Ansible tasks using the `google.cloud.gcp_sql_instance` or `gcp_sql_instance` module, ensure `settings.ip_configuration.authorized_networks` does not contain an entry with `value: "0.0.0.0"`; authorized networks should be explicit trusted CIDRs. If no `authorized_networks` are defined, `settings.ip_configuration.ipv4_enabled` must be set to `false` (or omitted/disabled) to prevent public IPv4 access. Resources missing `settings.ip_configuration` should be defined with a restricted `authorized_networks` list or have `ipv4_enabled: false`; instances with `value="0.0.0.0"` or with IPv4 enabled and no authorized networks will be flagged.

Secure configuration examples:

```yaml
- name: create Cloud SQL instance with restricted authorized networks
  google.cloud.gcp_sql_instance:
    name: my-sql
    settings:
      ip_configuration:
        authorized_networks:
          - name: office
            value: 203.0.113.0/24
        ipv4_enabled: true
```

```yaml
- name: create Cloud SQL instance without public IPv4
  google.cloud.gcp_sql_instance:
    name: my-sql
    settings:
      ip_configuration:
        ipv4_enabled: false
```

## Compliant Code Examples
```yaml
- name: sql_instance
  google.cloud.gcp_sql_instance:
    auth_kind: serviceaccount
    name: '{{ resource_name }}-2'
    project: test_project
    region: us-central1
    service_account_file: /tmp/auth.pem
    settings:
      ip_configuration:
        authorized_networks:
        - name: google dns server
          value: 8.8.8.8/32
      tier: db-n1-standard-1
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: sql_instance
  google.cloud.gcp_sql_instance:
    auth_kind: serviceaccount
    name: "{{ resource_name }}-2"
    project: test_project
    region: us-central1
    service_account_file: /tmp/auth.pem
    settings:
      ip_configuration:
        authorized_networks:
          - name: "google dns server"
            value: "0.0.0.0"
      tier: db-n1-standard-1
    state: present
- name: sql_instance2
  google.cloud.gcp_sql_instance:
    auth_kind: serviceaccount
    name: "{{ resource_name }}-2"
    project: test_project
    region: us-central1
    service_account_file: /tmp/auth.pem
    settings:
      ip_configuration:
        ipv4_enabled: yes
      tier: db-n1-standard-1
    state: present
- name: sql_instance3
  google.cloud.gcp_sql_instance:
    auth_kind: serviceaccount
    name: "{{ resource_name }}-2"
    project: test_project
    region: us-central1
    service_account_file: /tmp/auth.pem
    settings:
      tier: db-n1-standard-1
    state: present

```