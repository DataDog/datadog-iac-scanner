---
title: "Email alerts disabled"
group_id: "Terraform / Azure"
meta:
  name: "azure/email_alerts_disabled"
  id: "9db38e87-f6aa-4b5e-a1ec-7266df259409"
  display_name: "Email alerts disabled"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `9db38e87-f6aa-4b5e-a1ec-7266df259409`

**Cloud Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact)

### Description

Azure Security Center contact alert notifications should be enabled to ensure that designated security contacts receive email alerts about security issues or threats in your Azure environment. If the `alert_notifications` attribute is set to `false`, such as shown below, critical security incidents could go unnoticed, increasing the risk of delayed response to threats.

```
resource "azurerm_security_center_contact" "example" {
    email = "contact@example.com"
    phone = "+1-555-555-5555"
    alert_notifications = false
}
```

Setting `alert_notifications = true` ensures timely awareness and response to potential security incidents.

## Compliant Code Examples
```terraform
resource "azurerm_security_center_contact" "negative1" {
    email = "contact@example.com"
    phone = "+1-555-555-5555"
    alert_notifications = true
}
```
## Non-Compliant Code Examples
```terraform
resource "azurerm_security_center_contact" "positive1" {
    email = "contact@example.com"
    phone = "+1-555-555-5555"
   alert_notifications = false
}
```