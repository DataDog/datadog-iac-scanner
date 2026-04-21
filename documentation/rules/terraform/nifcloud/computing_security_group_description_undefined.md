---
title: "Nifcloud computing undefined description to security group"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/computing_security_group_description_undefined"
  id: "41c127a9-3a85-4bc3-a333-ed374eb9c3e4"
  display_name: "Nifcloud computing undefined description to security group"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `41c127a9-3a85-4bc3-a333-ed374eb9c3e4`

**Cloud Provider:** Nifcloud

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group#description)

### Description

Missing `description` for `nifcloud_security_group` resources. The `description` attribute must be present to support auditing and to document the purpose and intent of the security group. Resources without a `description` hinder security reviews and operational tracing.

## Compliant Code Examples
```terraform
resource "nifcloud_security_group" "negative" {
  group_name  = "http"
  description = "Allow inbound HTTP traffic"
}

```
## Non-Compliant Code Examples
```terraform
resource "nifcloud_security_group" "positive" {
  group_name  = "http"
}

```