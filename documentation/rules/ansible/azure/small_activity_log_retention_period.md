---
title: "Small activity log retention period"
group_id: "Ansible / Azure"
meta:
  name: "azure/small_activity_log_retention_period"
  id: "ansible-azure-small-activity-log-retention-period"
  display_name: "Small activity log retention period"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `ansible-azure-small-activity-log-retention-period`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_monitorlogprofile_module.html)

### Description

Activity Log retention must be configured to retain logs for at least 365 days (or indefinitely). Short retention windows hinder incident response, forensic investigations, and regulatory compliance.

For Ansible `azure.azcollection.azure_rm_monitorlogprofile` / `azure_rm_monitorlogprofile` resources, the `retention_policy.enabled` property must be `true` and `retention_policy.days` must be set to `365` or greater, or to `0` to retain logs indefinitely. Tasks that omit `retention_policy`, set `retention_policy.enabled` to `false` (or `no`), or set `retention_policy.days` to a value between 1 and 364 are flagged.

Secure configuration example:

```yaml
- name: Configure Activity Log retention
  azure.azcollection.azure_rm_monitorlogprofile:
    name: my-log-profile
    locations:
      - global
    categories:
      - Write
      - Delete
      - Action
    retention_policy:
      enabled: yes
      days: 365
```

## Compliant Code Examples
```yaml
- name: Create a log profile
  azure_rm_monitorlogprofile:
    name: myProfile
    location: eastus
    locations:
    - eastus
    - westus
    categories:
    - Write
    - Action
    retention_policy:
      enabled: true
      days: 380
    storage_account:
      resource_group: myResourceGroup
      name: myStorageAccount
  register: output

```
## Non-Compliant Code Examples
```yaml
---
- name: Create a log profile
  azure_rm_monitorlogprofile:
    name: myProfile
    location: eastus
    locations:
      - eastus
      - westus
    categories:
      - Write
      - Action
    retention_policy:
      enabled: False
    storage_account:
      resource_group: myResourceGroup
      name: myStorageAccount
  register: output

- name: Create a log profile2
  azure_rm_monitorlogprofile:
    name: myProfile
    location: eastus
    locations:
      - eastus
      - westus
    categories:
      - Write
      - Action
    storage_account:
      resource_group: myResourceGroup
      name: myStorageAccount
  register: output

- name: Create a log profile3
  azure_rm_monitorlogprofile:
    name: myProfile
    location: eastus
    locations:
      - eastus
      - westus
    categories:
      - Write
      - Action
    retention_policy:
      enabled: True
      days: 50
    storage_account:
      resource_group: myResourceGroup
      name: myStorageAccount
  register: output

```