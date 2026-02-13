---
title: "Beta - Nifcloud router has common private network"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/router_has_common_private"
  id: "30c2760c-740e-4672-9d7f-2c29e0cb385d"
  display_name: "Beta - Nifcloud router has common private network"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `30c2760c-740e-4672-9d7f-2c29e0cb385d`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/router#network_id)

### Description

 The `nifcloud_router` is configured to use the common private network (`net-COMMON_PRIVATE`). This rule detects `nifcloud_router` resources where `network_interface[_].network_id` or `network_interface.network_id` is set to `net-COMMON_PRIVATE`. The router should use a dedicated private LAN to isolate the private-side network from the shared network.


## Compliant Code Examples
```terraform
resource "nifcloud_router" "negative" {
  security_group  = nifcloud_security_group.example.group_name

  network_interface {
    network_id = nifcloud_private_lan.main.id
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_router" "positive" {
  security_group  = nifcloud_security_group.example.group_name

  network_interface {
    network_id = "net-COMMON_GLOBAL"
  }

  network_interface {
    network_id = "net-COMMON_PRIVATE"
  }
}

```

```terraform
resource "nifcloud_router" "positive" {
  security_group  = nifcloud_security_group.example.group_name

  network_interface {
    network_id = "net-COMMON_PRIVATE"
  }
}

```