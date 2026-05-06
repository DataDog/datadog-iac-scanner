---
title: "AKS monitoring logging disabled"
group_id: "Ansible / Azure"
meta:
  name: "azure/aks_monitoring_logging_disabled"
  id: "d5e83b32-56dd-4247-8c2e-074f43b38a5e"
  display_name: "AKS monitoring logging disabled"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** {{</* copyable-code */>}}d5e83b32-56dd-4247-8c2e-074f43b38a5e{{</* copyable-code */>}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_aks_module.html)

### Description

AKS clusters must have the monitoring addon enabled and configured to send logs and metrics to an Azure Log Analytics workspace. This ensures that cluster activity, security events, and configuration changes are visible for detection, alerting, and incident investigation.

For Ansible tasks using `azure_rm_aks` or `azure.azcollection.azure_rm_aks`, the `addon.monitoring` block must be present with `enabled` set to an Ansible-`true` value and `log_analytics_workspace_resource_id` set to the workspace resource ID. Tasks missing the `addon` or `addon.monitoring` blocks, missing `enabled` or the workspace ID, or with `enabled` not set to an Ansible-`true` value (for example `yes`, `true`, `on`, or `1`) are flagged.

Secure configuration example:

```yaml
- name: Create AKS cluster with monitoring enabled
  azure_rm_aks:
    name: myAKS
    resource_group: myRg
    addon:
      monitoring:
        enabled: yes
        log_analytics_workspace_resource_id: /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myRg/providers/Microsoft.OperationalInsights/workspaces/myWorkspace
```

## Compliant Code Examples
```yaml
- name: Create an AKS instance v4
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
    addon:
      monitoring:
        log_analytics_workspace_resource_id: qwqeqe
        enabled: yes

```
## Non-Compliant Code Examples
```yaml
- name: Create an AKS instance v0
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
    enable_rbac: yes
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
    enable_rbac: yes
    addon:
      http_application_routing:
        enabled: yes
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
      client_id: "cf72ca99-f6b9-4004-b0e0-bee10c521948"
      client_secret: "Password1234!"
    agent_pool_profiles:
      - name: default
        count: 1
        vm_size: Standard_DS1_v2
        type: VirtualMachineScaleSets
        max_count: 3
        min_count: 1
    enable_rbac: yes
    addon:
      monitoring:
        log_analytics_workspace_resource_id: "qwqeqe"
- name: Create an AKS instance v9
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
    enable_rbac: yes
    addon:
      monitoring:
        log_analytics_workspace_resource_id: "qwqeqe"
        enabled: no

```