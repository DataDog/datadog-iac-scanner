---
title: "Cloud Storage bucket versioning disabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/cloud_storage_bucket_versioning_disabled"
  id: "e7e961ac-d17e-4413-84bc-8a1fbe242944"
  display_name: "Cloud Storage bucket versioning disabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `e7e961ac-d17e-4413-84bc-8a1fbe242944`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#enabled)

### Description

 Enabling versioning on a Google Cloud Storage bucket ensures that previous versions of objects are preserved, preventing accidental or malicious data loss or overwrites. Without versioning enabled (for example, `versioning = { enabled = false }` or omitting the `versioning` block entirely), deleted or overwritten objects cannot be recovered, increasing the risk of permanent data loss. To mitigate this risk, enable versioning by setting `versioning = { enabled = true }` in your Terraform configuration:

```
resource "google_storage_bucket" "secure_example" {
  name     = "foo"
  location = "EU"

  versioning = {
    enabled = true
  }
}
```


## Compliant Code Examples
```terraform
resource "google_storage_bucket" "negative1" {
  name     = "foo"
  location = "EU"

  versioning = {
    enabled = true
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "google_storage_bucket" "positive1" {
  name     = "foo"
  location = "EU"

  versioning = {
    enabled = false
  }
}

resource "google_storage_bucket" "positive2" {
  name     = "foo"
  location = "EU"
}
```