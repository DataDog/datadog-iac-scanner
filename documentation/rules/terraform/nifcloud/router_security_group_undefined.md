---
title: "Beta - Nifcloud router undefined security group to router"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/router_security_group_undefined"
  id: "e7dada38-af20-4899-8955-dabea84ab1f0"
  display_name: "Beta - Nifcloud router undefined security group to router"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `e7dada38-af20-4899-8955-dabea84ab1f0`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/router#security_group)

### Description

`nifcloud_router` resources must include a `security_group` attribute.
Routers without a `security_group` lack explicit network access controls and may be insecure.
This rule flags any `nifcloud_router` missing `security_group` and reports attributes: `documentId`, `resourceType`, `resourceName`, `searchKey`, `issueType`, `keyExpectedValue`, `keyActualValue`.

## Compliant Code Examples
```terraform
resource "nifcloud_router" "negative" {
  security_group = nifcloud_security_group.router.group_name

  network_interface {
    network_id = "net-COMMON_GLOBAL"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_router" "positive" {
  network_interface {
    network_id = "net-COMMON_GLOBAL"
  }
}

```