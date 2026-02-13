---
title: "Beta - Nifcloud computing has common private network"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/computing_instance_has_common_private"
  id: "df58dd45-8009-43c2-90f7-c90eb9d53ed9"
  display_name: "Beta - Nifcloud computing has common private network"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `df58dd45-8009-43c2-90f7-c90eb9d53ed9`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/instance#network_id)

### Description

 The instance uses the common private network. The `nifcloud_instance` resource's `network_interface.network_id` is set to `net-COMMON_PRIVATE`. The instance should use a private LAN to isolate the private-side network from the shared network.


## Compliant Code Examples
```terraform
resource "nifcloud_instance" "negative" {
  image_id        = data.nifcloud_image.ubuntu.id
  security_group  = nifcloud_security_group.example.group_name
  network_interface {
    network_id = nifcloud_private_lan.main.id
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_instance" "positive" {
  image_id        = data.nifcloud_image.ubuntu.id
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
resource "nifcloud_instance" "positive" {
  image_id        = data.nifcloud_image.ubuntu.id
  security_group  = nifcloud_security_group.example.group_name
  network_interface {
    network_id = "net-COMMON_PRIVATE"
  }
}

```