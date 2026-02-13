---
title: "Beta - Nifcloud computing undefined description to security group rule"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/computing_security_group_rule_description_undefined"
  id: "e4610872-0b1c-4fb7-ab57-d81c0afdb291"
  display_name: "Beta - Nifcloud computing undefined description to security group rule"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `e4610872-0b1c-4fb7-ab57-d81c0afdb291`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group_rule#description)

### Description

 The `nifcloud_security_group_rule` resource must include a `description` attribute for auditing and traceability. This rule identifies `nifcloud_security_group_rule` instances that do not include a `description` and reports them as `MissingAttribute`. The rule returns `documentId`, `resourceType`, `resourceName`, `searchKey`, `issueType`, `keyExpectedValue`, and `keyActualValue` in the result.


## Compliant Code Examples
```terraform
resource "nifcloud_security_group_rule" "negative" {
  security_group_names = ["http"]
  type                 = "IN"
  description          = "HTTP from VPC"
  from_port            = 80
  to_port              = 80
  protocol             = "TCP"
  cidr_ip              = nifcloud_private_lan.main.cidr_block
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_security_group_rule" "positive" {
  security_group_names = ["http"]
  type                 = "IN"
  from_port            = 80
  to_port              = 80
  protocol             = "TCP"
  cidr_ip              = nifcloud_private_lan.main.cidr_block
}

```