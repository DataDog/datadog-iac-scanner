---
title: "AKS network policy misconfigured"
group_id: "Ansible / Azure"
meta:
  name: "azure/aks_network_policy_misconfigured"
  id: "ansible-azure-aks-network-policy-misconfigured"
  display_name: "AKS network policy misconfigured"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `ansible-azure-aks-network-policy-misconfigured`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_aks_module.html#parameter-network_profile/network_policy)

### Description

AKS clusters must have a network policy configured to enforce pod-to-pod network isolation and the principle of least privilege. Without a network policy, pods can communicate freely, increasing the risk of lateral movement and unintended access to services.

For Ansible resources using `azure.azcollection.azure_rm_aks` or `azure_rm_aks`, the `network_profile.network_policy` property must be defined and set to either `calico` or `azure`. Tasks that omit `network_profile` or `network_profile.network_policy`, or that set the property to any value other than `calico` or `azure`, are flagged.

Secure example Ansible task:

```yaml
- name: Create AKS cluster with network policy
  azure.azcollection.azure_rm_aks:
    name: my-aks-cluster
    resource_group: my-rg
    dns_prefix: myaks
    network_profile:
      network_policy: calico
```

## Compliant Code Examples
```yaml
- name: Create a managed Azure Container Services (AKS) instance01
  azure_rm_aks:
    name: myAKS
    location: eastus
    resource_group: myResourceGroup
    dns_prefix: akstest
    kubernetes_version: 1.14.6
    network_profile:
      network_policy: calico
    linux_profile:
      admin_username: azureuser
      ssh_key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAA...
    service_principal:
      client_id: cf72ca99-f6b9-4004-b0e0-bee10c521948
      client_secret: Password123!
    agent_pool_profiles:
    - name: default
      count: 5
      vm_size: Standard_D2_v2
    tags:
      Environment: Production
- name: Create a managed Azure Container Services (AKS) instance02
  azure_rm_aks:
    name: myAKS
    location: eastus
    resource_group: myResourceGroup
    dns_prefix: akstest
    kubernetes_version: 1.14.6
    network_profile:
      network_policy: azure
    linux_profile:
      admin_username: azureuser
      ssh_key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAA...
    service_principal:
      client_id: cf72ca99-f6b9-4004-b0e0-bee10c521948
      client_secret: Password123!
    agent_pool_profiles:
    - name: default
      count: 5
      vm_size: Standard_D2_v2
    tags:
      Environment: Production

```
## Non-Compliant Code Examples
```yaml
---
- name: Create a managed Azure Container Services (AKS) instance03
  azure_rm_aks:
    name: myAKS
    location: eastus
    resource_group: myResourceGroup
    dns_prefix: akstest
    kubernetes_version: 1.14.6
    network_profile:
      network_policy: istio
    linux_profile:
      admin_username: azureuser
      ssh_key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAA...
    service_principal:
      client_id: "cf72ca99-f6b9-4004-b0e0-bee10c521948"
      client_secret: "Password123!"
    agent_pool_profiles:
      - name: default
        count: 5
        vm_size: Standard_D2_v2
    tags:
      Environment: Production
- name: Create a managed Azure Container Services (AKS) instance04
  azure_rm_aks:
    name: myAKS
    location: eastus
    resource_group: myResourceGroup
    dns_prefix: akstest
    kubernetes_version: 1.14.6
    linux_profile:
      admin_username: azureuser
      ssh_key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAA...
    service_principal:
      client_id: "cf72ca99-f6b9-4004-b0e0-bee10c521948"
      client_secret: "Password123!"
    agent_pool_profiles:
      - name: default
        count: 5
        vm_size: Standard_D2_v2
    tags:
      Environment: Production

```