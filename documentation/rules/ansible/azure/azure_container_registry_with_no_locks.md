---
title: "Azure Container Registry with no locks"
group_id: "Ansible / Azure"
meta:
  name: "azure/azure_container_registry_with_no_locks"
  id: "ansible-azure-azure-container-registry-with-no-locks"
  display_name: "Azure Container Registry with no locks"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-azure-azure-container-registry-with-no-locks{{< /copyable-code >}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_lock_module.html)

### Description

Azure Container Registries must be protected by Azure resource locks to prevent accidental or unauthorized deletion or modification of container images and registry configuration.

In Ansible playbooks, tasks that create or manage ACRs using the `azure.azcollection.azure_rm_containerregistry` or `azure_rm_containerregistry` modules must be accompanied by a lock task using `azure.azcollection.azure_rm_lock` or `azure_rm_lock`. The lock should either target the specific registry—by having `managed_resource_id` contain the registry's `<register>.id`—or be scoped to the same `resource_group` as the registry (lock `resource_group` equals registry `resource_group`). Tasks without a corresponding lock task, or with locks that do not reference the registry by `managed_resource_id` nor share the same `resource_group`, are flagged.

## Compliant Code Examples
```yaml
- name: Create an azure container registry
  azure_rm_containerregistry:
    name: myRegistry
    location: eastus
    resource_group: myResourceGroup
    admin_user_enabled: true
    sku: Premium
    tags:
      Release: beta1
      Environment: Production
- name: Create a lock for a resource group
  azure_rm_lock:
    resource_group: myResourceGroup
    name: myLock
    level: read_only

```

```yaml
- name: Create an azure container registry11
  azure.azcollection.azure_rm_containerregistry:
    name: myRegistry
    location: eastus
    admin_user_enabled: "true"
    sku: Premium
    tags:
      Release: beta1
      Environment: Production
  register: acr2
- name: "Create lock for ACR11"
  azure.azcollection.azure_rm_lock:
    managed_resource_id: "{{ acr2.id }}"
    name: "acr_lock"
    level: can_not_delete

```
## Non-Compliant Code Examples
```yaml
- name: Create an azure container registryy1
  azure.azcollection.azure_rm_containerregistry:
    name: myRegistry
    location: eastus
    admin_user_enabled: "true"
    sku: Premium
    tags:
      Release: beta1
      Environment: Production
  register: acr
- name: "Create lock for ACR1"
  azure.azcollection.azure_rm_lock:
    managed_resource_id: "{{ acr3.id }}"
    name: "acr_lock"
    level: can_not_delete

```

```yaml
- name: Create an azure container registry
  azure_rm_containerregistry:
    name: myRegistry
    location: eastus
    resource_group: myResourceGroupFake
    admin_user_enabled: true
    sku: Premium
    tags:
      Release: beta1
      Environment: Production
- name: Create a lock for a resource group
  azure_rm_lock:
    resource_group: myResourceGroup32
    name: myLock
    level: read_only
- name: Create an azure container registry2
  azure.azcollection.azure_rm_containerregistry:
    name: myRegistry
    location: eastus
    resource_group: someResourceGroup
    admin_user_enabled: "true"
    sku: Premium
    tags:
      Release: beta1
      Environment: Production

```