---
title: "Beta - Nifcloud computing has public ingress security group rule"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/computing_instance_has_public_ingress_sgr"
  id: "b2ea2367-8dc9-4231-a035-d0b28bfa3dde"
  display_name: "Beta - Nifcloud computing has public ingress security group rule"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `b2ea2367-8dc9-4231-a035-d0b28bfa3dde`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group_rule#cidr_ip)

### Description

 An ingress `nifcloud_security_group_rule` allows traffic from a `/0` CIDR. The policy detects `nifcloud_security_group_rule` resources whose `cidr_ip` is `/0` (allowing traffic from anywhere) and flags them as insecure. The rule reports the following attributes: `documentId`, `resourceType`, `resourceName`, `searchKey`, `issueType`, `keyExpectedValue`, and `keyActualValue`.


## Compliant Code Examples
```terraform
resource "nifcloud_security_group_rule" "negative" {
  security_group_names = ["http"]
  type                 = "IN"
  description          = "HTTP from VPC"
  from_port            = 80
  to_port              = 80
  protocol             = "TCP"
  cidr_ip              = "10.0.0.0/16"
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_security_group_rule" "positive" {
  security_group_names = ["http"]
  type                 = "IN"
  description          = "HTTP from VPC"
  from_port            = 80
  to_port              = 80
  protocol             = "TCP"
  cidr_ip              = "0.0.0.0/0"
}

```