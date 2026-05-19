---
title: "Google project auto create network disabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/google_project_auto_create_network_disabled"
  id: "terraform-gcp-google-project-auto-create-network-disabled"
  display_name: "Google project auto create network disabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-gcp-google-project-auto-create-network-disabled{{< /copyable-code >}}

**Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project)

### Description

This check ensures that the `auto_create_network` attribute in the `google_project` resource is set to `false`. When `auto_create_network` is set to `true` or left unset (the default), Google Cloud automatically creates a default network with permissive firewall rules, potentially exposing resources to unauthorized access. Secure configuration requires explicitly setting `auto_create_network = false`, as shown below:

```
resource "google_project" "example" {
  name                = "My Project"
  project_id          = "your-project-id"
  org_id              = "1234567"
  auto_create_network = false
}
```

## Compliant Code Examples
```terraform
resource "google_project" "negative1" {
  name       = "My Project"
  project_id = "your-project-id"
  org_id     = "1234567"
  auto_create_network = false
}

```
## Non-Compliant Code Examples
```terraform
resource "google_project" "positive1" {
  name       = "My Project"
  project_id = "your-project-id"
  org_id     = "1234567"
  auto_create_network = true
}

resource "google_project" "positive2" {
  name       = "My Project"
  project_id = "your-project-id"
  org_id     = "1234567"
}

```