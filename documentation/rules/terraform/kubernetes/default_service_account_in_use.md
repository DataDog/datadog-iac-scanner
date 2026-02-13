---
title: "Default service account in use"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/default_service_account_in_use"
  id: "737a0dd9-0aaa-4145-8118-f01778262b8a"
  display_name: "Default service account in use"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `737a0dd9-0aaa-4145-8118-f01778262b8a`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/service_account#automount_service_account_token)

### Description

Default service accounts should not be actively used. The `kubernetes_service_account` resource named `default` must include the `automount_service_account_token` attribute and it must be set to `false`. If `automount_service_account_token` is missing, add `automount_service_account_token = false`; if it is set to `true`, replace it with `false`.

## Compliant Code Examples
```terraform
resource "kubernetes_service_account" "example3" {
  metadata {
    name = "default"
  }

  automount_service_account_token = false
}

```
## Non-Compliant Code Examples
```terraform
resource "kubernetes_service_account" "example" {
  metadata {
    name = "default"
  }
}

resource "kubernetes_service_account" "example2" {
  metadata {
    name = "default"
  }

  automount_service_account_token = true
}

```