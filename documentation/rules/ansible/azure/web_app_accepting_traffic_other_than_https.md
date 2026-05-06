---
title: "Web app accepting traffic other than HTTPS"
group_id: "Ansible / Azure"
meta:
  name: "azure/web_app_accepting_traffic_other_than_https"
  id: "eb8c2560-8bee-4248-9d0d-e80c8641dd91"
  display_name: "Web app accepting traffic other than HTTPS"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}eb8c2560-8bee-4248-9d0d-e80c8641dd91{{< /copyable-code >}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_webapp_module.html#parameter-https_only)

### Description

Azure Web Apps must accept only HTTPS traffic to protect data in transit from interception, tampering, and credential or session-token exposure. For Ansible deployments using the `azure_rm_webapp` or `azure.azcollection.azure_rm_webapp` module, the `https_only` property must be defined and set to `true` (or `yes`). Tasks that omit `https_only` or set it to a `false` value are flagged. 

Secure configuration example:

```yaml
- name: Create web app with HTTPS only
  azure.azcollection.azure_rm_webapp:
    name: my-webapp
    resource_group: my-rg
    plan: my-plan
    https_only: yes
```

## Compliant Code Examples
```yaml
- name: Create a windows web app with non-exist app service plan
  azure_rm_webapp:
    resource_group: myResourceGroup
    name: myWinWebapp
    https_only: true
    plan:
      resource_group: myAppServicePlan_rg
      name: myAppServicePlan
      is_linux: false
      sku: S1

```
## Non-Compliant Code Examples
```yaml
- name: Create a windows web app with non-exist app service plan
  azure_rm_webapp:
    resource_group: myResourceGroup
    name: myWinWebapp
    https_only: false
    plan:
      resource_group: myAppServicePlan_rg
      name: myAppServicePlan
      is_linux: false
      sku: S1
- name: Create another windows web app
  azure_rm_webapp:
    resource_group: myResourceGroup
    name: myWinWebapp
    plan:
      resource_group: myAppServicePlan_rg
      name: myAppServicePlan
      is_linux: false
      sku: S1

```