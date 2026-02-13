---
title: "Beta - Nifcloud ELB listener use HTTP protocol"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/elb_listener_use_http"
  id: "afcb0771-4f94-44ed-ad4a-9f73f11ce6e0"
  display_name: "Beta - Nifcloud ELB listener use HTTP protocol"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `afcb0771-4f94-44ed-ad4a-9f73f11ce6e0`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/elb_listener#protocol)

### Description

The ELB listener uses the HTTP protocol while its ELB network interface is in the 'net-COMMON_GLOBAL' VIP network. The listener should use HTTPS to enable TLS security features and protect data in transit.

## Compliant Code Examples
```terraform
resource "nifcloud_elb_listener" "negative" {
  elb_id        = nifcloud_elb.negative.id
  instance_port = 1443
  protocol      = "HTTPS"
  lb_port       = 1443
}

resource "nifcloud_elb" "negative" {
  availability_zone = "east-11"
  instance_port     = 443
  protocol          = "HTTPS"
  lb_port           = 443

  network_interface {
    network_id     = "net-COMMON_GLOBAL"
    is_vip_network = true
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_elb_listener" "positive" {
  elb_id        = nifcloud_elb.positive.id
  instance_port = 80
  protocol      = "HTTP"
  lb_port       = 80
}

resource "nifcloud_elb" "positive" {
  availability_zone = "east-11"
  instance_port     = 8080
  protocol          = "HTTP"
  lb_port           = 8080

  network_interface {
    network_id     = "net-COMMON_GLOBAL"
    is_vip_network = true
  }

  network_interface {
    network_id     = "net-COMMON_PRIVATE"
  }
}

```

```terraform
resource "nifcloud_elb_listener" "positive" {
  elb_id        = nifcloud_elb.positive.id
  instance_port = 80
  protocol      = "HTTP"
  lb_port       = 80
}

resource "nifcloud_elb" "positive" {
  availability_zone = "east-11"
  instance_port     = 8080
  protocol          = "HTTP"
  lb_port           = 8080

  network_interface {
    network_id     = "net-COMMON_GLOBAL"
    is_vip_network = true
  }
}

```