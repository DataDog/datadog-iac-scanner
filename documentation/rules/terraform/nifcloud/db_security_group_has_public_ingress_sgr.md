---
title: "NIFCLOUD RDB has public DB ingress security group rule"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/db_security_group_has_public_ingress_sgr"
  id: "terraform-nifcloud-db-security-group-has-public-ingress-sgr"
  display_name: "NIFCLOUD RDB has public DB ingress security group rule"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-nifcloud-db-security-group-has-public-ingress-sgr{{< /copyable-code >}}

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_security_group#cidr_ip)

### Description

A `nifcloud_db_security_group` ingress security group rule allows traffic from `/0`. The rule parses `rule[].cidr_ip`, splitting on `/` and converting the suffix to a number; it flags when that numeric mask is less than 1, indicating a CIDR of `/0`. This represents an overly permissive `cidr` range that allows traffic from any IP address.

## Compliant Code Examples
```terraform
resource "nifcloud_db_security_group" "negative" {
  group_name        = "example"
  availability_zone = "east-11"
  rule {
    cidr_ip = "10.0.0.0/16"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_db_security_group" "positive" {
  group_name        = "example"
  availability_zone = "east-11"
  rule {
    cidr_ip = "0.0.0.0/0"
  }
}

```