---
title: "Beta - Nifcloud NAS has common private network"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/nas_instance_has_common_private"
  id: "4b801c38-ebb4-4c81-984b-1ba525d43adf"
  display_name: "Beta - Nifcloud NAS has common private network"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `4b801c38-ebb4-4c81-984b-1ba525d43adf`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/nas_instance#network_id)

### Description

The NAS instance uses the shared private network `net-COMMON_PRIVATE` rather than an isolated private LAN. `nifcloud_nas_instance` resources should use a dedicated private LAN to isolate the private-side network from the shared network. This rule flags `nifcloud_nas_instance` resources that reference `net-COMMON_PRIVATE`.

## Compliant Code Examples
```terraform
resource "nifcloud_nas_instance" "negative" {
  identifier        = "nas001"
  allocated_storage = 100
  protocol          = "nfs"
  type              = 0
  network_id        = nifcloud_private_lan.main.id
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_nas_instance" "positive" {
  identifier        = "nas001"
  allocated_storage = 100
  protocol          = "nfs"
  type              = 0
  network_id        = "net-COMMON_PRIVATE"
}

```