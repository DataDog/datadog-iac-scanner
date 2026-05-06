---
title: "CosmosDB account IP range filter not set"
group_id: "Ansible / Azure"
meta:
  name: "azure/cosmosdb_account_ip_range_filter_not_set"
  id: "e8c80448-31d8-4755-85fc-6dbab69c2717"
  display_name: "CosmosDB account IP range filter not set"
  cloud_provider: "Azure"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}e8c80448-31d8-4755-85fc-6dbab69c2717{{< /copyable-code >}}

**Cloud Provider:** Azure

**Platform:** Ansible

**Severity:** Critical

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/azure/azcollection/azure_rm_cosmosdbaccount_module.html#parameter-ip_range_filter)

### Description

Cosmos DB accounts should have an IP range filter configured to restrict which client IP addresses can connect. Without one, the account may accept connections from unintended networks, increasing the risk of unauthorized data access.

In Ansible, the `azure.azcollection.azure_rm_cosmosdbaccount` (and legacy `azure_rm_cosmosdbaccount`) resource must include the `ip_range_filter` property set to the allowed IP addresses or CIDR ranges. Resources missing `ip_range_filter` or with it empty are flagged, as they indicate no network-level IP restrictions. Provide a comma-separated list of IPs/CIDRs to enforce access control.

Secure example with IP restrictions:

```yaml
- name: Create Cosmos DB account with IP restrictions
  azure.azcollection.azure_rm_cosmosdbaccount:
    resource_group: my-rg
    name: my-cosmosdb
    location: eastus
    offer_type: Standard
    ip_range_filter: "10.0.0.0/24,203.0.113.5"
```

## Compliant Code Examples
```yaml
- name: Create Cosmos DB Account - max
  azure_rm_cosmosdbaccount:
    resource_group: myResourceGroup
    name: myDatabaseAccount
    location: westus
    kind: mongo_db
    geo_rep_locations:
    - name: southcentralus
      failover_priority: 0
    database_account_offer_type: Standard
    ip_range_filter: 10.10.10.10
    enable_multiple_write_locations: yes
    virtual_network_rules:
    - subnet: /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVi
        rtualNetwork/subnets/mySubnet
    consistency_policy:
      default_consistency_level: bounded_staleness
      max_staleness_prefix: 10
      max_interval_in_seconds: 1000

```
## Non-Compliant Code Examples
```yaml
- name: Create Cosmos DB Account - max
  azure_rm_cosmosdbaccount:
    resource_group: myResourceGroup
    name: myDatabaseAccount
    location: westus
    kind: mongo_db
    geo_rep_locations:
      - name: southcentralus
        failover_priority: 0
    database_account_offer_type: Standard
    enable_multiple_write_locations: yes
    virtual_network_rules:
      - subnet: "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVi
                 rtualNetwork/subnets/mySubnet"
    consistency_policy:
      default_consistency_level: bounded_staleness
      max_staleness_prefix: 10
      max_interval_in_seconds: 1000

```