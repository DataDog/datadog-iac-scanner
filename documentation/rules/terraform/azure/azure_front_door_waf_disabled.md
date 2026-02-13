---
title: "Azure Front Door WAF disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/azure_front_door_waf_disabled"
  id: "835a4f2f-df43-437d-9943-545ccfc55961"
  display_name: "Azure Front Door WAF disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `835a4f2f-df43-437d-9943-545ccfc55961`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/frontdoor#web_application_firewall_policy_link_id)

### Description

 Azure Front Door should have a Web Application Firewall (WAF) enabled to protect applications from common web vulnerabilities and attacks such as SQL injection and cross-site scripting. If the `web_application_firewall_policy_link_id` attribute is not configured for the `frontend_endpoint` block, malicious traffic can reach backend resources without any inspection or filtering, increasing the risk of exploitation. To address this, ensure that WAF is linked, as shown below:

```
frontend_endpoint {
  name      = "exampleFrontendEndpoint1"
  host_name = "example-FrontDoor.azurefd.net"
  web_application_firewall_policy_link_id = "id"
}
```


## Compliant Code Examples
```terraform
resource "azurerm_frontdoor" "negative" {
  name                                         = "example-FrontDoor"
  resource_group_name                          = azurerm_resource_group.example.name
  enforce_backend_pools_certificate_name_check = false

  routing_rule {
    name               = "exampleRoutingRule1"
    accepted_protocols = ["Http", "Https"]
    patterns_to_match  = ["/*"]
    frontend_endpoints = ["exampleFrontendEndpoint1"]
    forwarding_configuration {
      forwarding_protocol = "MatchRequest"
      backend_pool_name   = "exampleBackendBing"
    }
  }

  backend_pool_load_balancing {
    name = "exampleLoadBalancingSettings1"
  }

  backend_pool_health_probe {
    name = "exampleHealthProbeSetting1"
  }

  backend_pool {
    name = "exampleBackendBing"
    backend {
      host_header = "www.bing.com"
      address     = "www.bing.com"
      http_port   = 80
      https_port  = 443
    }

    load_balancing_name = "exampleLoadBalancingSettings1"
    health_probe_name   = "exampleHealthProbeSetting1"
  }

  frontend_endpoint {
    name      = "exampleFrontendEndpoint1"
    host_name = "example-FrontDoor.azurefd.net"
    web_application_firewall_policy_link_id = "id"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_frontdoor" "positive" {
  name                                         = "example-FrontDoor"
  resource_group_name                          = azurerm_resource_group.example.name
  enforce_backend_pools_certificate_name_check = false

  routing_rule {
    name               = "exampleRoutingRule1"
    accepted_protocols = ["Http", "Https"]
    patterns_to_match  = ["/*"]
    frontend_endpoints = ["exampleFrontendEndpoint1"]
    forwarding_configuration {
      forwarding_protocol = "MatchRequest"
      backend_pool_name   = "exampleBackendBing"
    }
  }

  backend_pool_load_balancing {
    name = "exampleLoadBalancingSettings1"
  }

  backend_pool_health_probe {
    name = "exampleHealthProbeSetting1"
  }

  backend_pool {
    name = "exampleBackendBing"
    backend {
      host_header = "www.bing.com"
      address     = "www.bing.com"
      http_port   = 80
      https_port  = 443
    }

    load_balancing_name = "exampleLoadBalancingSettings1"
    health_probe_name   = "exampleHealthProbeSetting1"
  }

  frontend_endpoint {
    name      = "exampleFrontendEndpoint1"
    host_name = "example-FrontDoor.azurefd.net"
  }
}

```