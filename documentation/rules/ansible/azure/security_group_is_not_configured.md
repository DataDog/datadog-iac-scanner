---
title: "Security group is not configured"
group_id: "Ansible / Azure"
meta:
  name: "azure/security_group_is_not_configured"
  id: "ansible-azure-security-group-is-not-configured"
  display_name: "Security group is not configured"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `ansible-azure-security-group-is-not-configured`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_subnet_module.html)

### Description

A subnet without an associated Network Security Group (NSG) lacks network-level access controls, increasing exposure to unauthorized access and enabling lateral movement between resources.

For Ansible `azure_rm_subnet` resources (modules `azure.azcollection.azure_rm_subnet` and `azure_rm_subnet`), the `security_group` or `security_group_name` property must be defined and set to a non-empty value. Resources that omit these properties or set them to null/empty strings are flagged. Ensure the value references the appropriate NSG (name or ID) for your environment.

Secure configuration example:

```yaml
- name: Create subnet with NSG
  azure.azcollection.azure_rm_subnet:
    resource_group: my-rg
    virtual_network: my-vnet
    name: my-subnet
    address_prefix: 10.0.1.0/24
    security_group: my-nsg
```

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
- name: Create a subnet
  azure_rm_subnet:
    resource_group: myResourceGroup
    virtual_network_name: myVirtualNetwork
    name: mySubnet
    address_prefix_cidr: 10.1.0.0/24
    security_group: mySecurityGroup

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
- name: Create a subnet1
  azure_rm_subnet:
    resource_group: myResourceGroup1
    virtual_network_name: myVirtualNetwork1
    name: mySubnet1
    address_prefix_cidr: "10.1.0.0/24"
- name: Create a subnet2
  azure_rm_subnet:
    resource_group: myResourceGroup2
    virtual_network_name: myVirtualNetwork2
    name: mySubnet2
    address_prefix_cidr: "10.1.0.0/24"
    security_group:
- name: Create a subnet3
  azure_rm_subnet:
    resource_group: myResourceGroup3
    virtual_network_name: myVirtualNetwork3
    name: mySubnet3
    address_prefix_cidr: "10.1.0.0/24"
    security_group_name:
- name: Create a subnet4
  azure_rm_subnet:
    resource_group: myResourceGroup4
    virtual_network_name: myVirtualNetwork4
    name: mySubnet4
    address_prefix_cidr: "10.1.0.0/24"
    security_group: ""
- name: Create a subnet5
  azure_rm_subnet:
    resource_group: myResourceGroup5
    virtual_network_name: myVirtualNetwork5
    name: mySubnet5
    address_prefix_cidr: "10.1.0.0/24"
    security_group_name: ""

```