---
title: "Beta - Nifcloud RDB has common private network"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/db_instance_has_common_private"
  id: "9bf57c23-fbab-4222-85f3-3f207a53c6a8"
  display_name: "Beta - Nifcloud RDB has common private network"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `9bf57c23-fbab-4222-85f3-3f207a53c6a8`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#network_id)

### Description

`nifcloud_db_instance` is configured to use the common private LAN `net-COMMON_PRIVATE`. The resource's `network_id` should be a private LAN that isolates the private-side network from the shared network. This rule identifies `nifcloud_db_instance` resources that are using the common private network.

## Compliant Code Examples
```terraform
resource "nifcloud_db_instance" "negative" {
  identifier     = "example"
  instance_class = "db.large8"
  network_id     = nifcloud_private_lan.main.id
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_db_instance" "positive" {
  identifier     = "example"
  instance_class = "db.large8"
  network_id     = "net-COMMON_PRIVATE"
}

```