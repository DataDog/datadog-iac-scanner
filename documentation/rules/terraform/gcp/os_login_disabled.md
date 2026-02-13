---
title: "OSLogin disabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/os_login_disabled"
  id: "32ecd6eb-0711-421f-9627-1a28d9eff217"
  display_name: "OSLogin disabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `32ecd6eb-0711-421f-9627-1a28d9eff217`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_project_metadata#metadata)

### Description

 This check verifies whether the `enable-oslogin` metadata key is set to `true` in Google Cloud project or instance metadata, as shown below:

```
resource "google_compute_project_metadata" "secure_example" {
  metadata = {
    enable-oslogin = true
  }
}
```

If OS Login is not enabled, user and SSH key management is handled by instance-level metadata, which can lead to inconsistent access policies and increased risk of unauthorized access. Enabling OS Login centralizes and streamlines IAM-based SSH access, reducing the attack surface of compute resources.


## Compliant Code Examples
```terraform
resource "google_compute_project_metadata" "negative1" {
  metadata = {
    enable-oslogin = true
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "google_compute_project_metadata" "positive1" {
  metadata = {
    enable-oslogin = false
  }
}

resource "google_compute_project_metadata" "positive2" {
  metadata = {
      foo  = "bar"
  }
}

```