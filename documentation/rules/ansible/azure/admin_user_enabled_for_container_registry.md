---
title: "Admin user enabled for container registry"
group_id: "Ansible / Azure"
meta:
  name: "azure/admin_user_enabled_for_container_registry"
  id: "29f35127-98e6-43af-8ec1-201b79f99604"
  display_name: "Admin user enabled for container registry"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}29f35127-98e6-43af-8ec1-201b79f99604{{< /copyable-code >}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_containerregistry_module.html)

### Description

Enabling the admin user on an Azure Container Registry creates a shared username/password credential that can be leaked or abused to push or pull images, increasing the risk of unauthorized access and lateral movement.

For Ansible resources using `azure_rm_containerregistry` or `azure.azcollection.azure_rm_containerregistry`, the `admin_user_enabled` property must be set to `false` or omitted (it defaults to `false`). Tasks with `admin_user_enabled: true` are flagged. Use Azure AD RBAC with scoped service principals or managed identities for registry access instead. 

Secure example (explicitly disabling the admin user):

```yaml
- name: Create secure Azure Container Registry
  azure.azcollection.azure_rm_containerregistry:
    name: myRegistry
    resource_group: myResourceGroup
    sku: Basic
    admin_user_enabled: false
```

## Compliant Code Examples
```yaml
- name: Create an azure container registry
  azure.azcollection.azure_rm_containerregistry:
    name: myRegistry
    location: eastus
    resource_group: myResourceGroup
    admin_user_enabled: false
    sku: Premium
    tags:
      Release: beta1
      Environment: Production
- name: Create an azure container registry2
  azure.azcollection.azure_rm_containerregistry:
    name: myRegistry
    location: eastus
    resource_group: myResourceGroup
    admin_user_enabled: false
    sku: Premium
    tags:
      Release: beta1
      Environment: Production

```
## Non-Compliant Code Examples
```yaml
---
- name: Create an azure container registry
  azure.azcollection.azure_rm_containerregistry:
    name: myRegistry
    location: eastus
    resource_group: myResourceGroup
    admin_user_enabled: true
    sku: Premium
    tags:
      Release: beta1
      Environment: Production
- name: Create an azure container registry2
  azure.azcollection.azure_rm_containerregistry:
    name: myRegistry
    location: eastus
    resource_group: myResourceGroup
    admin_user_enabled: "true"
    sku: Premium
    tags:
      Release: beta1
      Environment: Production

```