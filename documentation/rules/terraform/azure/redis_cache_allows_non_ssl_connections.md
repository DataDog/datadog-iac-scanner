---
title: "Redis cache allows non SSL connections"
group_id: "Terraform / Azure"
meta:
  name: "azure/redis_cache_allows_non_ssl_connections"
  id: "e29a75e6-aba3-4896-b42d-b87818c16b58"
  display_name: "Redis cache allows non SSL connections"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `e29a75e6-aba3-4896-b42d-b87818c16b58`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache)

### Description

Allowing non-SSL connections to Azure Redis Cache resources exposes sensitive data in transit to potential interception or man-in-the-middle attacks, as information exchanged between clients and the Redis service will not be encrypted. To mitigate this risk, the `enable_non_ssl_port` attribute in the Terraform resource should be set to `false`, ensuring all connections use secure TLS communication. For example:

```
resource "azurerm_redis_cache" "secure_example" {
  name                = "example-cache"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"

  redis_configuration {
  }
}
```

Neglecting this configuration can lead to exposure of authentication credentials and cached data, increasing the risk of data breaches and compliance violations.

## Compliant Code Examples
```terraform
resource "azurerm_redis_cache" "negative1" {
  name                = "example-cache"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"

  redis_configuration {
  }
}

resource "azurerm_redis_cache" "negative2" {
  name                = "example-cache"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
 
  minimum_tls_version = "1.2"

  redis_configuration {
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_redis_cache" "positive1" {
  name                = "example-cache"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = true
  minimum_tls_version = "1.2"

  redis_configuration {
  }
}
```