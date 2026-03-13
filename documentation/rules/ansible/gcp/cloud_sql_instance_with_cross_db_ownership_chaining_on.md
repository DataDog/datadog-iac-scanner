---
title: "Cloud SQL instance with cross DB ownership chaining on"
group_id: "Ansible / GCP"
meta:
  name: "gcp/cloud_sql_instance_with_cross_db_ownership_chaining_on"
  id: "9e0c33ed-97f3-4ed6-8be9-bcbf3f65439f"
  display_name: "Cloud SQL instance with cross DB ownership chaining on"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `9e0c33ed-97f3-4ed6-8be9-bcbf3f65439f`

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_sql_instance_module.html#parameter-settings/database_flags)

### Description

SQL Server instances must have Cross DB Ownership Chaining disabled to prevent cross-database privilege escalation and lateral access between databases.

For Ansible-managed Google Cloud SQL resources (`google.cloud.gcp_sql_instance` or `gcp_sql_instance`), ensure the `settings.database_flags` entry with name `cross db ownership chaining` is present and its `value` is set to `off`. This check applies only when `database_version` indicates SQL Server. Instances missing the flag or with a value other than `off` are flagged.

Secure Ansible configuration example:

```yaml
- name: Create secure Cloud SQL SQLServer instance
  google.cloud.gcp_sql_instance:
    name: my-sqlserver-instance
    database_version: SQLSERVER_2019_STANDARD
    settings:
      tier: db-custom-1-3840
      database_flags:
        - name: "cross db ownership chaining"
          value: "off"
```

## Compliant Code Examples
```yaml
- name: sql_instance
  google.cloud.gcp_sql_instance:
    auth_kind: serviceaccount
    database_version: SQLSERVER_13_1
    name: '{{ resource_name }}-2'
    project: test_project
    region: us-central1
    service_account_file: /tmp/auth.pem
    settings:
      database_flags:
      - name: name1
        value: value1
      tier: db-n1-standard-1
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: sql_instance
  google.cloud.gcp_sql_instance:
    auth_kind: serviceaccount
    database_version: SQLSERVER_13_1
    name: "{{ resource_name }}-2"
    project: test_project
    region: us-central1
    service_account_file: /tmp/auth.pem
    settings:
      database_flags:
      - name: cross db ownership chaining
        value: on
      tier: db-n1-standard-1
    state: present

```