---
title: "NIFCLOUD VPN gateway undefined security group"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/vpn_gateway_security_group_undefined"
  id: "terraform-nifcloud-nifcloud-vpn-gateway-undefined-security-group"
  display_name: "NIFCLOUD VPN gateway undefined security group"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `terraform-nifcloud-nifcloud-vpn-gateway-undefined-security-group`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/vpn_gateway#security_group)

### Description

VPN gateway is missing `security_group`. `nifcloud_vpn_gateway` resources should include a `security_group` attribute for security purposes. This rule detects `nifcloud_vpn_gateway` resources that do not include a `security_group`, which can leave the VPN gateway exposed or indicate an incomplete configuration.

## Compliant Code Examples
```terraform
resource "nifcloud_vpn_gateway" "negative" {
  security_group  = nifcloud_security_group.example.group_name

  network_interface {
    network_id = "net-COMMON_GLOBAL"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_vpn_gateway" "positive" {
  network_interface {
    network_id = "net-COMMON_GLOBAL"
  }
}

```