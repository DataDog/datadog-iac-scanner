---
title: "Key Vault soft delete is disabled"
group_id: "Ansible / Azure"
meta:
  name: "azure/key_vault_soft_delete_is_disabled"
  id: "ansible-azure-key-vault-soft-delete-is-disabled"
  display_name: "Key Vault soft delete is disabled"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** `ansible-azure-key-vault-soft-delete-is-disabled`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_keyvault_module.html#parameter-enable_soft_delete)

### Description

Key Vaults must have soft delete enabled to prevent permanent loss of keys, secrets, and certificates. This ensures deleted items can be recovered after accidental or malicious deletion.

This rule checks Ansible tasks using the `azure.azcollection.azure_rm_keyvault` or `azure_rm_keyvault` modules and requires the `enable_soft_delete` property to be defined and set to `true`. Resources missing `enable_soft_delete` or with `enable_soft_delete: false` are flagged as insecure. Consider enabling purge protection for additional safeguards against permanent deletion.

Secure configuration example:

```yaml
- name: Create Key Vault with soft delete enabled
  azure.azcollection.azure_rm_keyvault:
    name: myKeyVault
    resource_group: myResourceGroup
    location: eastus
    sku: standard
    enable_soft_delete: true
```

## Compliant Code Examples
```yaml
- name: Create instance of Key Vault
  azure_rm_keyvault:
    resource_group: myResourceGroup
    vault_name: samplekeyvault
    enabled_for_deployment: yes
    enable_soft_delete: yes
    vault_tenant: 72f98888-8666-4144-9199-2d7cd0111111
    sku:
      name: standard
    access_policies:
    - tenant_id: 72f98888-8666-4144-9199-2d7cd0111111
      object_id: 99998888-8666-4144-9199-2d7cd0111111
      keys:
      - get
      - list

```
## Non-Compliant Code Examples
```yaml
---
- name: Create instance of Key Vault
  azure_rm_keyvault:
    resource_group: myResourceGroup
    vault_name: samplekeyvault
    enabled_for_deployment: yes
    enable_soft_delete: no
    vault_tenant: 72f98888-8666-4144-9199-2d7cd0111111
    sku:
      name: standard
    access_policies:
      - tenant_id: 72f98888-8666-4144-9199-2d7cd0111111
        object_id: 99998888-8666-4144-9199-2d7cd0111111
        keys:
          - get
          - list
- name: Create instance of Key Vault 02
  azure_rm_keyvault:
    resource_group: myResourceGroup 02
    vault_name: samplekeyvault
    enabled_for_deployment: yes
    vault_tenant: 72f98888-8666-4144-9199-2d7cd0111111
    sku:
      name: standard
    access_policies:
      - tenant_id: 72f98888-8666-4144-9199-2d7cd0111111
        object_id: 99998888-8666-4144-9199-2d7cd0111111
        keys:
          - get
          - list

```