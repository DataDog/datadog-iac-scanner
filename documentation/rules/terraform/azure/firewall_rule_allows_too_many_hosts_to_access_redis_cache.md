---
title: "Firewall rule allows too many hosts to access Redis Cache"
group_id: "Terraform / Azure"
meta:
  name: "azure/firewall_rule_allows_too_many_hosts_to_access_redis_cache"
  id: "a829b715-cf75-4e92-b645-54c9b739edfb"
  display_name: "Firewall rule allows too many hosts to access Redis Cache"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `a829b715-cf75-4e92-b645-54c9b739edfb`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_firewall_rule)

### Description

 This check assesses whether any Redis Cache firewall rule is configured to allow access from an overly broad IP range, such as specifying `start_ip = "1.0.0.0"` and `end_ip = "3.0.0.0"`. Allowing too many hosts to access the Redis Cache can expose sensitive data or enable unauthorized users to exploit the cache service. Firewall rules should narrowly define permitted IPs. For example:

```
resource "azurerm_redis_firewall_rule" "secure_example" {
  name                = "limitedAccess"
  redis_cache_name    = azurerm_redis_cache.example.name
  resource_group_name = azurerm_resource_group.example.name
  start_ip            = "1.2.3.4"
  end_ip              = "1.2.3.8"
}
```

Restricting access to only the necessary hosts mitigates the risk of data breaches and service misuse.


## Compliant Code Examples
```terraform
resource "azurerm_redis_firewall_rule" "negative1" {
  name                = "someIPrange"
  redis_cache_name    = azurerm_redis_cache.example.name
  resource_group_name = azurerm_resource_group.example.name
  start_ip            = "1.2.3.4"
  end_ip              = "1.2.3.8"
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_redis_firewall_rule" "positive1" {
  name                = "someIPrange"
  redis_cache_name    = azurerm_redis_cache.example.name
  resource_group_name = azurerm_resource_group.example.name
  start_ip            = "1.0.0.0"
  end_ip              = "3.0.0.0"
}
```