---
title: "Security contact email"
group_id: "Terraform / Azure"
meta:
  name: "azure/security_contact_email"
  id: "terraform-azure-security-contact-email"
  display_name: "Security contact email"
  cloud_provider: "Azure"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-azure-security-contact-email{{< /copyable-code >}}

**Provider:** Azure

**Platform:** Terraform

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#email)

### Description

Defining a security contact email in the `azurerm_security_center_contact` resource is essential for ensuring that security alerts and notifications from Azure are sent to the correct personnel. If the `email` attribute is omitted, as shown below, important security incidents may go unnoticed, increasing the risk of delayed responses to threats:

```
resource "azurerm_security_center_contact" "insecure" {
  phone = "+1-555-555-5555"
  alert_notifications = true
  alerts_to_admins    = true
}
```

To address this, always specify the `email` attribute to ensure security alerts reach a monitored mailbox:

```
resource "azurerm_security_center_contact" "secure" {
  email = "contact@example.com"
  phone = "+1-555-555-5555"
  alert_notifications = true
  alerts_to_admins    = true
}
```

## Compliant Code Examples
```terraform
resource "azurerm_security_center_contact" "negative" {
  email = "contact@example.com"
  phone = "+1-555-555-5555"

  alert_notifications = true
  alerts_to_admins    = true
}

```
## Non-Compliant Code Examples
```terraform
resource "azurerm_security_center_contact" "positive" {
  phone = "+1-555-555-5555"

  alert_notifications = true
  alerts_to_admins    = true
}

```