---
title: "Beta - Nifcloud ELB use HTTP protocol"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/elb_use_http"
  id: "e2de2b80-2fc2-4502-a764-40930dfcc70a"
  display_name: "Beta - Nifcloud ELB use HTTP protocol"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `e2de2b80-2fc2-4502-a764-40930dfcc70a`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/elb#protocol)

### Description

The ELB uses the HTTP protocol. This rule detects NIFCLOUD ELBs attached to the "net-COMMON_GLOBAL" VIP network (network_id == "net-COMMON_GLOBAL" and is_vip_network == true) that are configured with `protocol == "HTTP"`. Such ELBs should use HTTPS to benefit from TLS security features; the rule reports the resource with issueType `IncorrectValue` and indicates the expected and actual values.

## Compliant Code Examples
```terraform
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
resource "nifcloud_elb" "positive" {
  availability_zone = "east-11"
  instance_port     = 80
  protocol          = "HTTP"
  lb_port           = 80

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
resource "nifcloud_elb" "positive" {
  availability_zone = "east-11"
  instance_port     = 80
  protocol          = "HTTP"
  lb_port           = 80

  network_interface {
    network_id     = "net-COMMON_GLOBAL"
    is_vip_network = true
  }
}

```