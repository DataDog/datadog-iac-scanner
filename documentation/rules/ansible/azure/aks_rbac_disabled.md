---
title: "AKS RBAC disabled"
group_id: "Ansible / Azure"
meta:
  name: "azure/aks_rbac_disabled"
  id: "149fa56c-4404-4f90-9e25-d34b676d5b39"
  display_name: "AKS RBAC disabled"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `149fa56c-4404-4f90-9e25-d34b676d5b39`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_aks_module.html)

### Description

AKS clusters must have role-based access control (RBAC) enabled to restrict Kubernetes API operations to authorized principals and prevent privilege escalation or unauthorized cluster modifications.

In Ansible playbooks, tasks using the `azure.azcollection.azure_rm_aks` or `azure_rm_aks` modules must define the `enable_rbac` property and set it to a truthy value (for example `yes`/`true` or YAML true). Resources with `enable_rbac` missing or not set to a truthy value are flagged as insecure.

Secure Ansible example:

```yaml
- name: Create AKS cluster with RBAC enabled
  azure.azcollection.azure_rm_aks:
    name: myAKS
    resource_group: myRG
    enable_rbac: yes
```

## Compliant Code Examples
```yaml
- name: Create an AKS instance v3
  azure_rm_aks:
    name: myAKS
    resource_group: myResourceGroup
    location: eastus
    dns_prefix: akstest
    kubernetes_version: 1.14.6
    linux_profile:
      admin_username: azureuser
      ssh_key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAA...
    service_principal:
      client_id: cf72ca99-f6b9-4004-b0e0-bee10c521948
      client_secret: Password1234!
    agent_pool_profiles:
    - name: default
      count: 1
      vm_size: Standard_DS1_v2
      type: VirtualMachineScaleSets
      max_count: 3
      min_count: 1
    enable_rbac: yes

```
## Non-Compliant Code Examples
```yaml
- name: Create an AKS instance
  azure_rm_aks:
    name: myAKS
    resource_group: myResourceGroup
    location: eastus
    dns_prefix: akstest
    kubernetes_version: 1.14.6
    linux_profile:
      admin_username: azureuser
      ssh_key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAA...
    service_principal:
      client_id: "cf72ca99-f6b9-4004-b0e0-bee10c521948"
      client_secret: "Password1234!"
    agent_pool_profiles:
      - name: default
        count: 1
        vm_size: Standard_DS1_v2
        type: VirtualMachineScaleSets
        max_count: 3
        min_count: 1
    enable_rbac: no
- name: Create an AKS instance v2
  azure_rm_aks:
    name: myAKS
    resource_group: myResourceGroup
    location: eastus
    dns_prefix: akstest
    kubernetes_version: 1.14.6
    linux_profile:
      admin_username: azureuser
      ssh_key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAA...
    service_principal:
      client_id: "cf72ca99-f6b9-4004-b0e0-bee10c521948"
      client_secret: "Password1234!"
    agent_pool_profiles:
      - name: default
        count: 1
        vm_size: Standard_DS1_v2
        type: VirtualMachineScaleSets
        max_count: 3
        min_count: 1

```