---
title: "Beta - Nifcloud NAS has public ingress NAS security group rule"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/nas_security_group_has_public_ingress_sgr"
  id: "8d7758a7-d9cd-499a-a83e-c9bdcbff728d"
  display_name: "Beta - Nifcloud NAS has public ingress NAS security group rule"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `8d7758a7-d9cd-499a-a83e-c9bdcbff728d`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/nas_security_group#cidr_ip)

### Description

 An ingress `nifcloud_nas_security_group` rule allows traffic from `/0`. This permits access from the entire Internet and is overly permissive. Use a more restrictive CIDR range to limit allowed sources.


## Compliant Code Examples
```terraform
resource "nifcloud_nas_security_group" "negative" {
  group_name        = "nasgroup001"
  availability_zone = "east-11"

  rule {
    cidr_ip = "10.0.0.0/16"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_nas_security_group" "positive" {
  group_name        = "nasgroup001"
  availability_zone = "east-11"

  rule {
    cidr_ip = "0.0.0.0/0"
  }
}

```