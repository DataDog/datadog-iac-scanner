---
title: "Github organization webhook with SSL disabled"
group_id: "Terraform / GitHub"
meta:
  name: "github/organization_webhook_with_ssl_disabled"
  id: "terraform-github-organization-webhook-with-ssl-disabled"
  display_name: "Github organization webhook with SSL disabled"
  cloud_provider: "GitHub"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-github-organization-webhook-with-ssl-disabled{{< /copyable-code >}}

**Provider:** GitHub

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/github/latest/docs/resources/organization_webhook)

### Description

Check whether insecure SSL is used in GitHub organization webhooks.

## Compliant Code Examples
```terraform
resource "github_organization_webhook" "negative1" {
  name = "web"

  configuration {
    url          = "https://google.de/"
    content_type = "form"
    insecure_ssl = false
  }

  active = false

  events = ["issues"]
}
```
## Non-Compliant Code Examples
```terraform
resource "github_organization_webhook" "positive1" {
  name = "web"

  configuration {
    url          = "https://google.de/"
    content_type = "form"
    insecure_ssl = true
  }

  active = false

  events = ["issues"]
}
```