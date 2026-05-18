---
title: "Cloud SQL instance with contained database authentication on"
group_id: "Ansible / GCP"
meta:
  name: "gcp/cloud_sql_instance_with_contained_database_authentication_on"
  id: "ansible-gcp-cloud-sql-instance-with-contained-database-authentication-on"
  display_name: "Cloud SQL instance with contained database authentication on"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-cloud-sql-instance-with-contained-database-authentication-on{{< /copyable-code >}}

**Cloud Provider:** GCP

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_sql_instance_module.html#parameter-settings/database_flags)

### Description

Cloud SQL for SQL Server instances must have Contained Database Authentication disabled. Contained database users authenticate at the database level, bypassing server-level authentication and centralized IAM controls. This increases the risk of unauthorized access and unmanaged credentials.

For Ansible `google.cloud.gcp_sql_instance` or `gcp_sql_instance` resources, ensure `settings.database_flags` includes an entry with `name: "contained database authentication"` and `value: "off"`. Resources that omit this flag or set it to any value other than `"off"` are flagged. The check evaluates the `settings.database_flags` entries.

Secure configuration example:

- name: Create Cloud SQL SQL Server instance
  google.cloud.gcp_sql_instance:
    name: my-sqlserver-instance
    database_version: SQLSERVER_2019_STANDARD
    settings:
      database_flags:
        - name: contained database authentication
          value: "off"

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
      - name: contained database authentication
        value: on
      tier: db-n1-standard-1
    state: present

```