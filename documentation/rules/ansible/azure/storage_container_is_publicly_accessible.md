---
title: "Storage container is publicly accessible"
group_id: "Ansible / Azure"
meta:
  name: "azure/storage_container_is_publicly_accessible"
  id: "4d3817db-dd35-4de4-a80d-3867157e7f7f"
  display_name: "Storage container is publicly accessible"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** {{</* copyable-code */>}}4d3817db-dd35-4de4-a80d-3867157e7f7f{{</* copyable-code */>}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_storageblob_module.html#parameter-public_access)

### Description

Allowing anonymous public read access to Azure Blob Storage containers or their blobs exposes stored data to anyone on the internet, increasing the risk of data exfiltration and compliance violations. In Ansible tasks using `azure.azcollection.azure_rm_storageblob` or `azure_rm_storageblob`, the `public_access` property must not be set to `"blob"` or `"container"`.

The rule flags tasks where `public_access` (case-insensitive) equals `blob` or `container`. Setting it to `blob` permits anonymous read of individual blobs, while `container` also allows listing container contents. To remediate, omit the `public_access` property or set it to `private`. Use SAS tokens, Azure RBAC, private endpoints, or signed URLs for controlled sharing.

Secure example:

```yaml
- name: Create storage blob container (private)
  azure.azcollection.azure_rm_storageblob:
    resource_group: my-rg
    account_name: my-storage-account
    container: my-container
    public_access: private
```

## Compliant Code Examples
```yaml
- name: Create container foo and upload a file
  azure_rm_storageblob:
    resource_group: myResourceGroup
    storage_account_name: clh0002
    container: foo
    blob: graylog.png
    src: ./files/graylog.png
    content_type: application/image
# access mode defaults to private

```
## Non-Compliant Code Examples
```yaml
- name: Create container foo and upload a file
  azure_rm_storageblob:
    resource_group: myResourceGroup
    storage_account_name: clh0002
    container: foo
    blob: graylog.png
    src: ./files/graylog.png
    content_type: 'application/image'
    public_access: blob
- name: Create container foo2 and upload a file
  azure_rm_storageblob:
    resource_group: myResourceGroup
    storage_account_name: clh0002
    container: foo2
    blob: graylog.png
    src: ./files/graylog.png
    public_access: container
    content_type: 'application/image'

```