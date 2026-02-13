---
title: "Beta - Nifcloud ELB has common private network"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/elb_has_common_private"
  id: "5061f84c-ab66-4660-90b9-680c9df346c0"
  display_name: "Beta - Nifcloud ELB has common private network"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `5061f84c-ab66-4660-90b9-680c9df346c0`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/elb#network_id)

### Description

 The `nifcloud_elb` is configured to use the shared private network `net-COMMON_PRIVATE`.
This exposes the private side to the shared network and should instead use a dedicated private LAN to maintain isolation.
The rule flags any `nifcloud_elb` where `network_interface.network_id` equals `net-COMMON_PRIVATE`.


## Compliant Code Examples
```terraform
resource "nifcloud_elb" "negative" {
  availability_zone = "east-11"
  instance_port     = 80
  protocol          = "HTTP"
  lb_port           = 80
  network_interface {
    network_id = nifcloud_private_lan.main.id
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_elb" "positive" {
  availability_zone = "east-11"
  instance_port     = 80
  protocol          = "HTTP"
  lb_port           = 80
  network_interface {
    network_id = "net-COMMON_GLOBAL"
  }
  network_interface {
    network_id = "net-COMMON_PRIVATE"
  }
}

```

```terraform
resource "nifcloud_elb" "positive" {
  availability_zone = "east-11"
  instance_port     = 80
  protocol          = "HTTP"
  lb_port           = 80
  network_interface {
    network_id = "net-COMMON_PRIVATE"
  }
}

```