---
title: "NIFCLOUD computing undefined description to security group"
group_id: "Terraform / Nifcloud"
meta:
  name: "nifcloud/computing_security_group_description_undefined"
  id: "terraform-nifcloud-computing-security-group-description-undefined"
  display_name: "NIFCLOUD computing undefined description to security group"
  cloud_provider: "Nifcloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-nifcloud-computing-security-group-description-undefined{{< /copyable-code >}}

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