---
title: "WAF is disabled for Azure Application Gateway"
group_id: "Ansible / Azure"
meta:
  name: "azure/waf_is_disabled_for_azure_application_gateway"
  id: "2fc5ab5a-c5eb-4ae4-b687-0f16fe77c255"
  display_name: "WAF is disabled for Azure Application Gateway"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}2fc5ab5a-c5eb-4ae4-b687-0f16fe77c255{{< /copyable-code >}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_appgateway_module.html)

### Description

Application Gateway instances must have the Web Application Firewall (WAF) SKU enabled to protect web traffic from application-layer threats like SQL injection, cross-site scripting, and automated attacks.

For Ansible resources using `azure.azcollection.azure_rm_appgateway` or `azure_rm_appgateway`, the `sku.tier` property must be set to `WAF` or `WAF_v2` (case-insensitive) to enable WAF capabilities. Resources missing `sku.tier` or configured with non-WAF tiers (for example `Standard` or `Standard_v2`) are flagged as insecure.

Secure configuration example:

```yaml
- name: Create Application Gateway with WAF_v2
  azure.azcollection.azure_rm_appgateway:
    resource_group: myResourceGroup
    name: myAppGateway
    sku:
      tier: WAF_v2
```

## Compliant Code Examples
```yaml
- name: Create instance of Application Gateway
  azure_rm_appgateway:
    resource_group: myResourceGroup
    name: myAppGateway
    sku:
      name: waf_medium
      tier: waf
      capacity: 2

```
## Non-Compliant Code Examples
```yaml
- name: Create instance of Application Gateway
  azure_rm_appgateway:
    resource_group: myResourceGroup
    name: myAppGateway
    sku:
      name: standard_small
      tier: standard
      capacity: 2

```