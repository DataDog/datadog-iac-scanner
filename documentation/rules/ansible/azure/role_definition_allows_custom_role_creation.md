---
title: "Role definition allows custom role creation"
group_id: "Ansible / Azure"
meta:
  name: "azure/role_definition_allows_custom_role_creation"
  id: "ansible-azure-role-definition-allows-custom-role-creation"
  display_name: "Role definition allows custom role creation"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `ansible-azure-role-definition-allows-custom-role-creation`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_roledefinition_module.html#parameter-permissions/actions)

### Description

Role definitions must not grant the ability to create or modify other role definitions (`Microsoft.Authorization/roleDefinitions/write`). This capability enables privilege escalation and persistent unauthorized access by allowing creation of custom roles with elevated permissions.

In Ansible playbooks using the `azure.azcollection.azure_rm_roledefinition` or `azure_rm_roledefinition` modules, the `permissions[].actions` array must not include the literal action `Microsoft.Authorization/roleDefinitions/write` and must not be a wildcard (`*`). This rule flags tasks where `permissions.actions` is `["*"]` or contains `Microsoft.Authorization/roleDefinitions/write`. Ensure the actions list contains only the specific, least-privilege actions required for the role.

Secure example with no role-definition write permission:

```yaml
- name: example role
  azure.azcollection.azure_rm_roledefinition:
    name: customReadOnlyRole
    scope: /subscriptions/00000000-0000-0000-0000-000000000000
    permissions:
      - actions:
          - "Microsoft.Storage/storageAccounts/read"
          - "Microsoft.Compute/virtualMachines/read"
```

## Compliant Code Examples
```yaml
---
- name: Create a role definition3
  azure_rm_roledefinition:
    name: myTestRole3
    scope: /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myresourceGroup
    permissions:
      - actions:
          - "Microsoft.Compute/virtualMachines/read"
        data_actions:
          - "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
    assignable_scopes:
      - "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

```
## Non-Compliant Code Examples
```yaml
---
- name: Create a role definition2
  azure_rm_roledefinition:
    name: myTestRole2
    scope: /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myresourceGroup
    permissions:
      - actions:
          - "*"
    assignable_scopes:
      - "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

```

```yaml
---
- name: Create a role definition
  azure_rm_roledefinition:
    name: myTestRole
    scope: /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myresourceGroup
    permissions:
      - actions:
          - "Microsoft.Authorization/roleDefinitions/write"
    assignable_scopes:
      - "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

```