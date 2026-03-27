---
title: "Cosmos DB account without tags"
group_id: "Ansible / Azure"
meta:
  name: "azure/cosmosdb_account_without_tags"
  id: "23a4dc83-4959-4d99-8056-8e051a82bc1e"
  display_name: "Cosmos DB account without tags"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `23a4dc83-4959-4d99-8056-8e051a82bc1e`

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_cosmosdbaccount_module.html)

### Description

Cosmos DB account resources must include tags to support asset identification, ownership, and automated security or incident response processes. Without tags, inventory, cost allocation, and security triage become more difficult.

For Ansible, tasks using the `azure.azcollection.azure_rm_cosmosdbaccount` or `azure_rm_cosmosdbaccount` modules must define the `tags` property as a mapping of key-value pairs. Resources missing the `tags` property or with it undefined are flagged. Include keys such as Owner and Environment to enable governance and automation.

Secure example:

```yaml
- name: create cosmosdb account
  azure.azcollection.azure_rm_cosmosdbaccount:
    name: my-cosmosdb
    resource_group: my-rg
    location: eastus
    kind: GlobalDocumentDB
    offer_type: Standard
    tags:
      Owner: team-abc
      Environment: production
      Project: billing-service
```

## Compliant Code Examples
```yaml
- name: Create Cosmos DB Account - min
  azure_rm_cosmosdbaccount:
    resource_group: myResourceGroup
    name: myDatabaseAccount
    location: westus
    geo_rep_locations:
    - name: southcentralus
      failover_priority: 0
    database_account_offer_type: Standard
    tags:
      t1: t1
      t2: t2

```
## Non-Compliant Code Examples
```yaml
---
- name: Create Cosmos DB Account - min
  azure_rm_cosmosdbaccount:
    resource_group: myResourceGroup
    name: myDatabaseAccount
    location: westus
    geo_rep_locations:
      - name: southcentralus
        failover_priority: 0
    database_account_offer_type: Standard

```