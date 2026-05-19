---
title: "MySQL instance with local infile on"
group_id: "Ansible / GCP"
meta:
  name: ""gcp/mysql_instance_with_local_infile_on""
  id: "ansible-gcp-mysql-instance-with-local-infile-on"
  display_name: "MySQL instance with local infile on"
  cloud_provider: "GCP"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-gcp-mysql-instance-with-local-infile-on{{< /copyable-code >}}

**Provider:** GCP

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_sql_instance_module.html#parameter-settings/database_flags)

### Description

MySQL instances must have the `local_infile` flag disabled. Enabling `LOAD DATA LOCAL INFILE` can be abused to read or exfiltrate files via SQL operations or by malicious servers and clients, exposing sensitive data. For Ansible tasks using `google.cloud.gcp_sql_instance` or `gcp_sql_instance`, ensure the `settings.database_flags` list contains an entry with `name: local_infile` and `value: "off"` for instances whose `database_version` contains "MYSQL". Resources missing this flag or with `local_infile` set to any value other than `"off"` are flagged as insecure.

Secure configuration example:

```yaml
- name: create MySQL Cloud SQL instance with local_infile disabled
  google.cloud.gcp_sql_instance:
    name: my-instance
    database_version: MYSQL_5_7
    settings:
      database_flags:
        - name: local_infile
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
    database_version: MYSQL_5_6
    name: "{{ resource_name }}-2"
    project: test_project
    region: us-central1
    service_account_file: /tmp/auth.pem
    settings:
      database_flags:
      - name: local_infile
        value: on
      tier: db-n1-standard-1
    state: present

```