---
title: "SQL DB instance with SSL disabled"
group_id: "Ansible / GCP"
meta:
  name: "gcp/sql_db_instance_with_ssl_disabled"
  id: "d0f7da39-a2d5-4c78-bb85-4b7f338b3cbb"
  display_name: "SQL DB instance with SSL disabled"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `d0f7da39-a2d5-4c78-bb85-4b7f338b3cbb`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_sql_instance_module.html#parameter-settings/ip_configuration/require_ssl)

### Description

Cloud SQL instances must require SSL for client connections to protect data in transit and prevent unauthorized or unencrypted access to the database. In Ansible tasks using the `google.cloud.gcp_sql_instance` or `gcp_sql_instance` module, the `settings.ip_configuration.require_ssl` property must be set to `true`. Resources that omit `settings.ip_configuration.require_ssl` or set it to `false` are flagged as a misconfiguration.

Secure Ansible task example:

```yaml
- name: Create Cloud SQL instance with SSL required
  google.cloud.gcp_sql_instance:
    project: my-project
    name: my-sql-instance
    settings:
      tier: db-f1-micro
      ip_configuration:
        require_ssl: true
```

## Compliant Code Examples
```yaml
- name: create a instance
  google.cloud.gcp_sql_instance:
    name: '{{ resource_name }}-2'
    settings:
      ip_configuration:
        require_ssl: yes
        authorized_networks:
        - name: google dns server
          value: 8.8.8.8/32
      tier: db-n1-standard-1
    region: us-central1
    project: test_project
    auth_kind: serviceaccount
    service_account_file: /tmp/auth.pem
    state: present

```
## Non-Compliant Code Examples
```yaml
---
- name: create a instance
  google.cloud.gcp_sql_instance:
    name: "{{ resource_name }}-2"
    region: us-central1
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a second instance
  google.cloud.gcp_sql_instance:
    name: "{{ resource_name }}-2"
    settings:
      tier: db-n1-standard-1
    region: us-central1
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a third instance
  google.cloud.gcp_sql_instance:
    name: "{{ resource_name }}-2"
    settings:
      ip_configuration:
        authorized_networks:
        - name: google dns server
          value: 8.8.8.8/32
      tier: db-n1-standard-1
    region: us-central1
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present
- name: create a forth instance
  google.cloud.gcp_sql_instance:
    name: "{{ resource_name }}-2"
    settings:
      ip_configuration:
        require_ssl: no
        authorized_networks:
        - name: google dns server
          value: 8.8.8.8/32
      tier: db-n1-standard-1
    region: us-central1
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
    state: present

```