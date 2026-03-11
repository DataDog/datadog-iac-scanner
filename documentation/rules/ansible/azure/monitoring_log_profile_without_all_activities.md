---
title: "Monitoring Log Profile Without All Activities"
group_id: "Ansible / Azure"
meta:
  name: "azure/monitoring_log_profile_without_all_activities"
  id: "89f84a1e-75f8-47c5-83b5-bee8e2de4168"
  display_name: "Monitoring Log Profile Without All Activities"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `89f84a1e-75f8-47c5-83b5-bee8e2de4168`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_monitorlogprofile_module.html)

### Description

Monitor log profiles must include the Write, Action, and Delete categories so Azure records operations, configuration changes, and deletions for detection, auditing, and forensic investigations. In Ansible tasks using `azure.azcollection.azure_rm_monitorlogprofile` (or `azure_rm_monitorlogprofile`), the `categories` property must be defined as a list and include the values `Write`, `Action`, and `Delete` (case-insensitive). Tasks missing the `categories` property or omitting any of these categories will be flagged.

Secure configuration example:

```yaml
- name: Create monitor log profile
  azure_rm_monitorlogprofile:
    name: myLogProfile
    categories:
      - Write
      - Action
      - Delete
    locations:
      - eastus
    retention_policy:
      enabled: false
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
    - Delete
    retention_policy:
      enabled: false
      days: 1
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
      days: 1
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
    retention_policy:
      enabled: False
      days: 1
    storage_account:
      resource_group: myResourceGroup
      name: myStorageAccount
  register: output

```